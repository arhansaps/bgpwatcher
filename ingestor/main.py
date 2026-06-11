"""
BGP Stream Ingestor

Connects to the RIPE RIS Live WebSocket feed, subscribes to UPDATE messages,
normalizes them into per-prefix events, and publishes each event to the
Kafka `bgp.raw` topic.
"""

import asyncio
import json
import logging
import os

import websockets
from aiokafka import AIOKafkaProducer

RIS_LIVE_URL = "wss://ris-live.ripe.net/v1/ws/?client=bgpwatch"
KAFKA_BOOTSTRAP_SERVERS = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
KAFKA_TOPIC = "bgp.raw"

SUBSCRIBE_MESSAGE = {
    "type": "ris_subscribe",
    "data": {
        "type": "UPDATE",
    },
}

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("ingestor")


def normalize_update(msg: dict):
    """Turn a single RIS Live UPDATE message into one event per prefix."""
    data = msg["data"]

    timestamp = data.get("timestamp")
    peer = data.get("peer")
    peer_asn = data.get("peer_asn")
    as_path = data.get("path", [])
    origin_asn = as_path[-1] if as_path else None

    events = []

    for announcement in data.get("announcements", []):
        next_hop = announcement.get("next_hop")
        for prefix in announcement.get("prefixes", []):
            events.append({
                "timestamp": timestamp,
                "peer": peer,
                "peer_asn": peer_asn,
                "type": "announcement",
                "prefix": prefix,
                "as_path": as_path,
                "origin_asn": origin_asn,
                "path_length": len(as_path),
                "next_hop": next_hop,
            })

    for prefix in data.get("withdrawals", []):
        events.append({
            "timestamp": timestamp,
            "peer": peer,
            "peer_asn": peer_asn,
            "type": "withdrawal",
            "prefix": prefix,
            "as_path": None,
            "origin_asn": None,
            "path_length": None,
            "next_hop": None,
        })

    return events


async def get_producer():
    producer = AIOKafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        key_serializer=lambda k: k.encode("utf-8") if k else None,
    )
    while True:
        try:
            await producer.start()
            log.info("connected to Kafka at %s", KAFKA_BOOTSTRAP_SERVERS)
            return producer
        except Exception as exc:
            log.warning("kafka not ready (%s), retrying in 5s", exc)
            await asyncio.sleep(5)


async def consume():
    producer = await get_producer()

    try:
        async for ws in websockets.connect(RIS_LIVE_URL, ping_interval=20, ping_timeout=20):
            try:
                log.info("connected to RIS Live")
                await ws.send(json.dumps(SUBSCRIBE_MESSAGE))

                async for raw in ws:
                    msg = json.loads(raw)

                    if msg.get("type") != "ris_message":
                        continue

                    for event in normalize_update(msg):
                        await producer.send_and_wait(KAFKA_TOPIC, value=event, key=event["prefix"])

            except websockets.ConnectionClosed:
                log.warning("connection closed, reconnecting...")
                continue
    finally:
        await producer.stop()


if __name__ == "__main__":
    asyncio.run(consume())
