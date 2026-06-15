"""
State Manager

Consumes normalized BGP events from `bgp.raw`, maintains a per-prefix
routing baseline in Redis, and writes each event to TimescaleDB for
historical queries.
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone

import asyncpg
import redis.asyncio as redis
from aiokafka import AIOKafkaConsumer

KAFKA_BOOTSTRAP_SERVERS = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
KAFKA_TOPIC = "bgp.raw"
REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
POSTGRES_DSN = os.environ.get("POSTGRES_DSN", "postgresql://bgpwatch:bgpwatch@localhost:5432/bgpwatch")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("state")

INSERT_QUERY = """
    INSERT INTO bgp_updates (time, prefix, peer, peer_asn, type, as_path, origin_asn, path_length, next_hop)
    VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9)
"""


async def get_consumer():
    consumer = AIOKafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
        group_id="state-manager",
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


def baseline_key(prefix: str) -> str:
    return f"baseline:{prefix}"


def normalize_origin_asn(origin_asn):
    """origin_asn can be an AS_SET (list) for aggregated paths; flatten to a single ASN or None."""
    if isinstance(origin_asn, list):
        return origin_asn[0] if origin_asn else None
    return origin_asn


async def update_baseline(redis_client, event):
    key = baseline_key(event["prefix"])

    if event["type"] == "withdrawal":
        await redis_client.hset(key, mapping={"state": "withdrawn", "last_seen": event["timestamp"]})
        return

    await redis_client.hset(key, mapping={
        "state": "announced",
        "origin_asn": normalize_origin_asn(event["origin_asn"]) or "",
        "as_path": json.dumps(event["as_path"]),
        "path_length": event["path_length"],
        "peer_asn": event["peer_asn"] or "",
        "next_hop": event["next_hop"] or "",
        "last_seen": event["timestamp"],
    })


async def write_history(pool, event):
    peer_asn = int(event["peer_asn"]) if event["peer_asn"] is not None else None
    origin_asn = normalize_origin_asn(event["origin_asn"])

    await pool.execute(
        INSERT_QUERY,
        datetime.fromtimestamp(event["timestamp"], tz=timezone.utc),
        event["prefix"],
        event["peer"],
        peer_asn,
        event["type"],
        json.dumps(event["as_path"]),
        origin_asn,
        event["path_length"],
        event["next_hop"],
    )


async def consume():
    consumer = await get_consumer()
    redis_client = await get_redis()
    pg_pool = await get_pg_pool()

    try:
        async for msg in consumer:
            event = msg.value
            await update_baseline(redis_client, event)
            await write_history(pg_pool, event)
    finally:
        await consumer.stop()
        await redis_client.aclose()
        await pg_pool.close()


if __name__ == "__main__":
    asyncio.run(consume())
