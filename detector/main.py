"""
Anomaly Detector

Consumes normalized BGP events from `bgp.raw`. For each announcement:
  1. Runs 4 rule-based checks (origin change, subprefix, path spike, new transit AS)
  2. If any rule fires, scores the event with a pre-trained Isolation Forest
  3. Publishes anomalies to `bgp.anomalies` and records them in TimescaleDB

The model artifact (model.joblib) is produced by train.py and must exist
before this service starts.
"""

import asyncio
import json
import logging
import math
import os
from collections import Counter
from datetime import datetime, timezone

import asyncpg
import joblib
import numpy as np
import pytricia
import redis.asyncio as redis
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from aiokafka.admin import AIOKafkaAdminClient, NewTopic
from aiokafka.errors import TopicAlreadyExistsError

KAFKA_BOOTSTRAP_SERVERS = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
INPUT_TOPIC = "bgp.raw"
OUTPUT_TOPIC = "bgp.anomalies"
REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
POSTGRES_DSN = os.environ.get("POSTGRES_DSN", "postgresql://bgpwatch:bgpwatch@localhost:5432/bgpwatch")
MODEL_PATH = os.environ.get("MODEL_PATH", "model.joblib")

# How often to rebuild the prefix trie from Redis (seconds)
TRIE_REFRESH_INTERVAL = 300
# Path length multiplier threshold for spike detection
PATH_SPIKE_MULTIPLIER = 2.0
# Isolation Forest score threshold — scores below this (more negative = more anomalous)
# trigger the anomaly; IF raw scores are in roughly [-0.5, 0.5]
ANOMALY_SCORE_THRESHOLD = float(os.environ.get("ANOMALY_SCORE_THRESHOLD", "0.0"))
# TTL for known-origins sets in Redis
ORIGINS_TTL_SECONDS = 7 * 24 * 60 * 60

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("detector")

INSERT_QUERY = """
    INSERT INTO bgp_anomalies
        (time, prefix, type, peer, peer_asn, old_origin_asn, new_origin_asn, as_path,
         anomaly_score, triggered_rules)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10::jsonb)
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def normalize_origin_asn(origin_asn):
    if isinstance(origin_asn, list):
        return origin_asn[0] if origin_asn else None
    return origin_asn


def origins_key(prefix: str) -> str:
    return f"detector:origins:{prefix}"


def baseline_key(prefix: str) -> str:
    return f"baseline:{prefix}"


def path_entropy(as_path: list) -> float:
    if not as_path:
        return 0.0
    counts = Counter(as_path)
    total = len(as_path)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def prefix_cidr_len(prefix: str) -> int:
    try:
        return int(prefix.split("/")[1])
    except (IndexError, ValueError):
        return 0


# ---------------------------------------------------------------------------
# Startup / connection helpers
# ---------------------------------------------------------------------------

async def ensure_topic_exists(topic: str):
    admin = AIOKafkaAdminClient(bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS)
    await admin.start()
    try:
        await admin.create_topics([NewTopic(name=topic, num_partitions=1, replication_factor=1)])
        log.info("created topic %s", topic)
    except TopicAlreadyExistsError:
        pass
    finally:
        await admin.close()


async def get_consumer():
    consumer = AIOKafkaConsumer(
        INPUT_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
        group_id="detector",
        auto_offset_reset="latest",
    )
    while True:
        try:
            await consumer.start()
            log.info("connected to Kafka at %s", KAFKA_BOOTSTRAP_SERVERS)
            return consumer
        except Exception as exc:
            log.warning("kafka not ready (%s), retrying in 5s", exc)
            await asyncio.sleep(5)


async def get_producer():
    producer = AIOKafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        key_serializer=lambda k: k.encode("utf-8") if k else None,
    )
    while True:
        try:
            await producer.start()
            return producer
        except Exception as exc:
            log.warning("kafka not ready (%s), retrying in 5s", exc)
            await asyncio.sleep(5)


async def get_redis():
    while True:
        try:
            client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
            await client.ping()
            log.info("connected to Redis at %s:%s", REDIS_HOST, REDIS_PORT)
            return client
        except Exception as exc:
            log.warning("redis not ready (%s), retrying in 5s", exc)
            await asyncio.sleep(5)


async def get_pg_pool():
    while True:
        try:
            pool = await asyncpg.create_pool(POSTGRES_DSN)
            log.info("connected to Postgres")
            return pool
        except Exception as exc:
            log.warning("postgres not ready (%s), retrying in 5s", exc)
            await asyncio.sleep(5)


# ---------------------------------------------------------------------------
# Prefix trie (rebuilt periodically from Redis baseline)
# ---------------------------------------------------------------------------

async def build_prefix_trie(redis_client) -> pytricia.PyTricia:
    """Scan all baseline keys in Redis and populate a prefix trie."""
    trie = pytricia.PyTricia()
    cursor = 0
    while True:
        cursor, keys = await redis_client.scan(cursor, match="baseline:*", count=500)
        for key in keys:
            prefix = key[len("baseline:"):]
            origin = await redis_client.hget(key, "origin_asn")
            if origin:
                try:
                    trie[prefix] = int(origin)
                except (ValueError, KeyError):
                    pass
        if cursor == 0:
            break
    log.info("prefix trie built with %d entries", len(trie))
    return trie


async def trie_refresh_loop(redis_client, state: dict):
    """Background task: rebuild the prefix trie every TRIE_REFRESH_INTERVAL seconds."""
    while True:
        await asyncio.sleep(TRIE_REFRESH_INTERVAL)
        try:
            state["trie"] = await build_prefix_trie(redis_client)
        except Exception as exc:
            log.warning("trie refresh failed: %s", exc)


# ---------------------------------------------------------------------------
# Rule checks
# ---------------------------------------------------------------------------

async def rule_origin_change(redis_client, event) -> bool:
    """New origin ASN for a prefix that already has known origins."""
    new_origin = normalize_origin_asn(event["origin_asn"])
    if new_origin is None:
        return False

    key = origins_key(event["prefix"])
    card = await redis_client.scard(key)
    is_known = await redis_client.sismember(key, new_origin)

    await redis_client.sadd(key, new_origin)
    await redis_client.expire(key, ORIGINS_TTL_SECONDS)

    return card > 0 and not is_known


async def rule_subprefix(redis_client, trie: pytricia.PyTricia, event) -> bool:
    """A more-specific prefix is announced by a different AS than the covering prefix."""
    prefix = event["prefix"]
    new_origin = normalize_origin_asn(event["origin_asn"])
    if new_origin is None:
        return False

    try:
        parent = trie.parent(prefix)
    except (KeyError, ValueError):
        parent = None

    if parent is None:
        return False

    parent_origin = trie.get(parent)
    if parent_origin is None:
        return False

    return int(new_origin) != int(parent_origin)


async def rule_path_spike(redis_client, event) -> bool:
    """Current path length is more than PATH_SPIKE_MULTIPLIER times the last known."""
    current_len = event.get("path_length")
    if not current_len:
        return False

    baseline = await redis_client.hgetall(baseline_key(event["prefix"]))
    if not baseline:
        return False

    try:
        last_len = int(baseline.get("path_length", 0))
    except (ValueError, TypeError):
        return False

    if last_len == 0:
        return False

    return current_len > last_len * PATH_SPIKE_MULTIPLIER


def rule_new_transit_as(graph, event) -> list[int]:
    """Return ASes in the path not previously seen as transit for this origin."""
    as_path = event.get("as_path") or []
    if len(as_path) < 2:
        return []

    origin = normalize_origin_asn(event["origin_asn"])
    if origin is None:
        return []

    origin = int(origin)
    if origin not in graph:
        return []

    unknown = [
        int(asn) for asn in as_path[:-1]
        if not graph.has_edge(origin, int(asn))
    ]
    return unknown


# ---------------------------------------------------------------------------
# ML scoring
# ---------------------------------------------------------------------------

def score_event(model, scaler, graph, event) -> float:
    """Return the Isolation Forest anomaly score for this event.

    IF scores: positive = normal, negative = anomalous.
    We return the raw score; caller decides threshold.
    """
    as_path = event.get("as_path") or []
    origin = normalize_origin_asn(event["origin_asn"])
    origin = int(origin) if origin is not None else 0

    new_as_count = sum(
        1 for asn in as_path[:-1]
        if origin in graph and not graph.has_edge(origin, int(asn))
    ) if origin in graph else len(as_path) - 1

    features = np.array([[
        event.get("path_length") or 0,
        path_entropy(as_path),
        prefix_cidr_len(event["prefix"]),
    ]], dtype=float)

    features_scaled = scaler.transform(features)
    score = model.score_samples(features_scaled)[0]
    return float(score)


# ---------------------------------------------------------------------------
# Main consume loop
# ---------------------------------------------------------------------------

async def write_anomaly(pool, anomaly):
    await pool.execute(
        INSERT_QUERY,
        datetime.fromtimestamp(anomaly["timestamp"], tz=timezone.utc),
        anomaly["prefix"],
        anomaly["type"],
        anomaly["peer"],
        int(anomaly["peer_asn"]) if anomaly["peer_asn"] is not None else None,
        anomaly["old_origin_asn"],
        anomaly["new_origin_asn"],
        json.dumps(anomaly["as_path"]),
        anomaly["anomaly_score"],
        json.dumps(anomaly["triggered_rules"]),
    )


async def consume():
    log.info("loading model from %s", MODEL_PATH)
    artifacts = joblib.load(MODEL_PATH)
    model = artifacts["model"]
    scaler = artifacts["scaler"]
    graph = artifacts["graph"]
    log.info("model loaded — AS graph has %d nodes", graph.number_of_nodes())

    await ensure_topic_exists(OUTPUT_TOPIC)

    consumer = await get_consumer()
    producer = await get_producer()
    redis_client = await get_redis()
    pg_pool = await get_pg_pool()

    trie_state = {"trie": await build_prefix_trie(redis_client)}
    asyncio.create_task(trie_refresh_loop(redis_client, trie_state))

    try:
        async for msg in consumer:
            event = msg.value
            if event["type"] != "announcement":
                continue

            trie = trie_state["trie"]

            # Run rules concurrently where possible
            origin_fired, subprefix_fired, spike_fired = await asyncio.gather(
                rule_origin_change(redis_client, event),
                rule_subprefix(redis_client, trie, event),
                rule_path_spike(redis_client, event),
            )
            new_transit_asns = rule_new_transit_as(graph, event)
            transit_fired = len(new_transit_asns) > 0

            triggered = []
            if origin_fired:
                triggered.append("origin_change")
            if subprefix_fired:
                triggered.append("subprefix")
            if spike_fired:
                triggered.append("path_spike")
            if transit_fired:
                triggered.append("new_transit_as")

            if not triggered:
                continue

            score = score_event(model, scaler, graph, event)

            # Suppress if IF says this looks normal
            if score > ANOMALY_SCORE_THRESHOLD:
                log.debug(
                    "suppressed %s for %s (rules: %s, score: %.3f)",
                    triggered, event["prefix"], triggered, score,
                )
                continue

            origin = normalize_origin_asn(event["origin_asn"])
            anomaly = {
                "timestamp": event["timestamp"],
                "prefix": event["prefix"],
                "type": triggered[0],  # primary type is the first triggered rule
                "peer": event["peer"],
                "peer_asn": event["peer_asn"],
                "old_origin_asn": None,
                "new_origin_asn": int(origin) if origin is not None else None,
                "as_path": event["as_path"],
                "anomaly_score": score,
                "triggered_rules": triggered,
            }

            log.info(
                "anomaly: %s for %s (rules: %s, score: %.3f)",
                triggered[0], event["prefix"], triggered, score,
            )
            await producer.send_and_wait(OUTPUT_TOPIC, value=anomaly, key=event["prefix"])
            await write_anomaly(pg_pool, anomaly)
    finally:
        await consumer.stop()
        await producer.stop()
        await redis_client.aclose()
        await pg_pool.close()


if __name__ == "__main__":
    asyncio.run(consume())
