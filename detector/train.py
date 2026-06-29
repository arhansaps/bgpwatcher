"""
Offline training script for the bgpwatch ML detector.

Downloads recent RIPE RIS MRT update files, extracts BGP feature vectors,
trains an Isolation Forest, and builds an AS topology graph (NetworkX).
Both artifacts are serialized to model.joblib.

Usage:
    python train.py [--files N] [--rrc RRC] [--output PATH]

    --files N      Number of 5-minute MRT update files to download (default: 12 = 1 hour)
    --rrc RRC      RIPE route collector to use, e.g. rrc00 (default: rrc00)
    --output PATH  Output path for model.joblib (default: model.joblib)
"""

import argparse
import gzip
import io
import logging
import math
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta

import joblib
import networkx as nx
import requests
import mrtparse
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import numpy as np

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("train")

RIPE_BASE = "https://data.ris.ripe.net"


def list_recent_update_urls(rrc: str, n_files: int) -> list[str]:
    """Return URLs for the N most recent 5-minute update files for a given RRC."""
    now = datetime.now(timezone.utc)
    urls = []
    # Walk back through 5-minute slots until we have enough
    slot = now.replace(second=0, microsecond=0)
    slot = slot.replace(minute=(slot.minute // 5) * 5)

    while len(urls) < n_files:
        ym = slot.strftime("%Y.%m")
        ts = slot.strftime("%Y%m%d.%H%M")
        url = f"{RIPE_BASE}/{rrc}/{ym}/updates.{ts}.gz"
        urls.append(url)
        slot -= timedelta(minutes=5)

    return urls


def download_mrt(url: str) -> bytes | None:
    try:
        resp = requests.get(url, timeout=30)
        if resp.status_code == 200:
            log.info("downloaded %s (%d bytes)", url, len(resp.content))
            return resp.content
        log.warning("HTTP %d for %s", resp.status_code, url)
        return None
    except Exception as exc:
        log.warning("failed to download %s: %s", url, exc)
        return None


def extract_as_path(path_attrs: list) -> list[int]:
    """Pull the flat AS_SEQUENCE from a BGP path attributes list."""
    for attr in path_attrs:
        type_val = attr.get("type", [])
        # mrtparse encodes type as [(code, name), ...]
        type_name = type_val[0][1] if type_val and isinstance(type_val[0], tuple) else ""
        if type_name != "AS_PATH":
            continue
        for segment in attr.get("value", []):
            seg_type = segment.get("type", [])
            seg_type_name = seg_type[0][1] if seg_type and isinstance(seg_type[0], tuple) else ""
            if seg_type_name == "AS_SEQUENCE":
                return [int(asn) for asn in segment.get("value", [])]
    return []


def path_entropy(as_path: list[int]) -> float:
    if not as_path:
        return 0.0
    counts = Counter(as_path)
    total = len(as_path)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def prefix_len(prefix: str) -> int:
    try:
        return int(prefix.split("/")[1])
    except (IndexError, ValueError):
        return 0


def parse_mrt_bytes(data: bytes) -> list[dict]:
    """Parse a gzipped MRT update file and return a list of BGP announcement records."""
    records = []
    try:
        raw = gzip.decompress(data)
    except Exception as exc:
        log.warning("failed to decompress MRT data: %s", exc)
        return records

    try:
        reader = mrtparse.Reader(io.BytesIO(raw))
        for entry in reader:
            try:
                d = entry.data
                # Only care about BGP4MP UPDATE messages
                mrt_type = d.get("type", [])
                mrt_type_name = mrt_type[0][1] if mrt_type and isinstance(mrt_type[0], tuple) else ""
                if mrt_type_name not in ("BGP4MP", "BGP4MP_ET"):
                    continue

                bgp_msg = d.get("bgp_message", {})
                msg_type = bgp_msg.get("type", [])
                msg_type_name = msg_type[0][1] if msg_type and isinstance(msg_type[0], tuple) else ""
                if msg_type_name != "UPDATE":
                    continue

                path_attrs = bgp_msg.get("path_attributes", [])
                as_path = extract_as_path(path_attrs)
                if not as_path:
                    continue

                origin_asn = as_path[-1]
                nlri = bgp_msg.get("nlri", [])

                for route in nlri:
                    pfx = route.get("prefix", "")
                    plen = route.get("length", 0)
                    if not pfx:
                        continue
                    prefix_str = f"{pfx}/{plen}"
                    records.append({
                        "prefix": prefix_str,
                        "as_path": as_path,
                        "origin_asn": origin_asn,
                        "path_length": len(as_path),
                        "path_entropy": path_entropy(as_path),
                        "prefix_len": plen,
                    })
            except Exception:
                continue
    except Exception as exc:
        log.warning("MRT parse error: %s", exc)

    return records


def build_artifacts(records: list[dict]):
    """Train IsolationForest and build NetworkX AS graph from parsed records."""
    log.info("building artifacts from %d records", len(records))

    # AS topology graph: edge (origin_asn, transit_asn) means transit_asn has been
    # seen in a path for origin_asn
    graph = nx.Graph()
    for rec in records:
        origin = rec["origin_asn"]
        for asn in rec["as_path"][:-1]:  # all except origin
            graph.add_edge(origin, asn)

    log.info("AS graph: %d nodes, %d edges", graph.number_of_nodes(), graph.number_of_edges())

    # Feature matrix: [path_length, path_entropy, prefix_len, new_as_count]
    # new_as_count at training time is always 0 (all ASes in training paths are known),
    # so we store the graph and compute it at inference. For training features we use
    # [path_length, path_entropy, prefix_len] only — new_as_count is purely a rule signal.
    X = np.array([
        [r["path_length"], r["path_entropy"], r["prefix_len"]]
        for r in records
    ], dtype=float)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    log.info("training IsolationForest on %d samples...", len(X_scaled))
    model = IsolationForest(n_estimators=200, contamination=0.01, random_state=42, n_jobs=-1)
    model.fit(X_scaled)
    log.info("training complete")

    return {"model": model, "scaler": scaler, "graph": graph}


def main():
    parser = argparse.ArgumentParser(description="Train bgpwatch ML detector")
    parser.add_argument("--files", type=int, default=12, help="Number of MRT update files to download (default: 12 = 1 hour)")
    parser.add_argument("--rrc", default="rrc00", help="RIPE route collector (default: rrc00)")
    parser.add_argument("--output", default="model.joblib", help="Output path (default: model.joblib)")
    args = parser.parse_args()

    urls = list_recent_update_urls(args.rrc, args.files)
    log.info("will attempt to download %d files from %s", len(urls), args.rrc)

    all_records = []
    for url in urls:
        data = download_mrt(url)
        if data:
            records = parse_mrt_bytes(data)
            log.info("  parsed %d announcements", len(records))
            all_records.extend(records)

    if not all_records:
        log.error("no records parsed — check network access or try a different --rrc")
        sys.exit(1)

    artifacts = build_artifacts(all_records)
    joblib.dump(artifacts, args.output)
    log.info("model saved to %s", args.output)


if __name__ == "__main__":
    main()
