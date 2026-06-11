"""
BGP Stream Ingestor

Connects to the RIPE RIS Live WebSocket feed, subscribes to UPDATE messages,
and emits normalized BGP route events (one per announced/withdrawn prefix).

For now this just logs events to stdout. Once Kafka is wired up, normalized
events will be published to the `bgp.raw` topic instead.
"""

import asyncio
import json
import logging

import websockets

RIS_LIVE_URL = "wss://ris-live.ripe.net/v1/ws/?client=bgpwatch"

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


async def consume():
    async for ws in websockets.connect(RIS_LIVE_URL, ping_interval=20, ping_timeout=20):
        try:
            log.info("connected to RIS Live")
            await ws.send(json.dumps(SUBSCRIBE_MESSAGE))

            async for raw in ws:
                msg = json.loads(raw)

                if msg.get("type") != "ris_message":
                    continue

                for event in normalize_update(msg):
                    log.info(json.dumps(event))

        except websockets.ConnectionClosed:
            log.warning("connection closed, reconnecting...")
            continue


if __name__ == "__main__":
    asyncio.run(consume())
