"""
Anomaly Detector

Consumes normalized BGP events from `bgp.raw`, tracks the last-seen origin
ASN for each prefix in Redis, and flags origin ASN changes (a classic
prefix-hijack indicator) as anomalies. Anomalies are published to the
Kafka `bgp.anomalies` topic and recorded in TimescaleDB.
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone

import asyncpg
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

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("detector")

INSERT_QUERY = """
    INSERT INTO bgp_anomalies (time, prefix, type, peer, peer_asn, old_origin_asn, new_origin_asn, as_path)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
"""


def normalize_origin_asn(origin_asn):
    """origin_asn can be an AS_SET (list) for aggregated paths; flatten to a single ASN or None."""
    if isinstance(origin_asn, list):
        return origin_asn[0] if origin_asn else None
    return origin_asn


ORIGINS_TTL_SECONDS = 7 * 24 * 60 * 60  # forget origins not seen for a week


def origins_key(prefix: str) -> str:
    return f"detector:origins:{prefix}"


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


async def check_origin_change(redis_client, event):
    """Flag origin ASNs that have never been seen announcing this prefix before.

    Prefixes are often legitimately announced by more than one ASN (MOAS, e.g.
    anycast). Rather than alerting on every switch between known origins, we
    track the set of origins seen for each prefix and only alert the first
    time a new origin shows up.
    """
    if event["type"] != "announcement":
        return None

    new_origin = normalize_origin_asn(event["origin_asn"])
    if new_origin is None:
        return None

    key = origins_key(event["prefix"])
    is_known = await redis_client.sismember(key, new_origin)

    is_first_sighting = await redis_client.scard(key) == 0

    await redis_client.sadd(key, new_origin)
    await redis_client.expire(key, ORIGINS_TTL_SECONDS)

    if not is_known and not is_first_sighting:
        return {
            "timestamp": event["timestamp"],
            "prefix": event["prefix"],
            "type": "new_origin",
            "peer": event["peer"],
            "peer_asn": event["peer_asn"],
            "old_origin_asn": None,
            "new_origin_asn": int(new_origin),
            "as_path": event["as_path"],
        }

    return None


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
    )


async def consume():
    await ensure_topic_exists(OUTPUT_TOPIC)

    consumer = await get_consumer()
    producer = await get_producer()
    redis_client = await get_redis()
    pg_pool = await get_pg_pool()

    try:
        async for msg in consumer:
            event = msg.value
            anomaly = await check_origin_change(redis_client, event)
            if anomaly is None:
                continue

            log.info("new origin for %s: AS%s", anomaly["prefix"], anomaly["new_origin_asn"])
            await producer.send_and_wait(OUTPUT_TOPIC, value=anomaly, key=anomaly["prefix"])
            await write_anomaly(pg_pool, anomaly)
    finally:
        await consumer.stop()
        await producer.stop()
        await redis_client.aclose()
        await pg_pool.close()


if __name__ == "__main__":
    asyncio.run(consume())
