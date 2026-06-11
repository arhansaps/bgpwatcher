# bgpwatch

Real-time BGP route anomaly detection system. Ingests live internet routing data, detects hijacks and prefix leaks using ML, and ships alerts through a production-grade observability stack.

---

## What it does

BGP (Border Gateway Protocol) is the protocol that tells the internet how to route traffic between autonomous systems (ASes). A BGP hijack happens when a malicious or misconfigured AS announces ownership of IP prefixes it doesn't control — rerouting traffic through unintended paths. This has taken down YouTube, compromised AWS Route 53, and hit dozens of major networks.

bgpwatch connects to a live BGP update feed, maintains a per-prefix routing baseline, and flags anomalies in real time — unexpected origin AS changes, subprefix hijacks, path prepend attacks, and new transit AS appearances.

---

## Architecture

```
RIPE RIS Live / BGPStream (WebSocket)
            |
    BGP Stream Ingestor (Python)
            |
      Kafka [bgp.raw]
     /       |        \
    /        |         \
Anomaly   State      Metrics
Detector  Manager    Exporter
    |         |           |
Isolation  PostgreSQL  Prometheus
Forest +   TimescaleDB     |
NetworkX       |        Grafana
    |       Redis
Kafka      (baseline
[bgp.      cache)
anomalies]
    |
Alertmanager
    |
FastAPI (query + alert API)
```

---

## Tech Stack

| Component | Tool | Why |
|---|---|---|
| BGP data source | RIPE RIS Live / BGPStream | Live + historical internet BGP feeds, free |
| Message bus | Kafka | Decouples ingestion from processing; handles burst UPDATE events; enables replay for model tuning |
| Anomaly detection | Python — Isolation Forest + NetworkX | Isolation Forest on AS path features; NetworkX builds the AS topology graph for structural path analysis |
| Routing baseline | Redis | Low-latency per-prefix state cache for real-time comparison |
| Storage | PostgreSQL + TimescaleDB | TimescaleDB extension for efficient time-series queries on BGP metrics and alert history |
| Metrics | Prometheus | Instruments update ingestion rate, anomaly scores, Kafka consumer lag, alert fire rate |
| Dashboards | Grafana | Live anomaly score per prefix, AS path change heatmap, alert history |
| Alert routing | Alertmanager | Deduplicates repeated alerts for the same hijacked prefix; routes to configured channels |
| Query API | FastAPI | REST endpoints for current routing state, per-prefix anomaly history, active alerts |
| Infra | Docker Compose | Single-command local setup for all services |

---

## Anomaly Detection

Four detection signals, each derived from parsed BGP UPDATE messages:

**Origin AS change** — prefix previously announced by AS X is now announced by AS Y. Strongest hijack signal.

**Subprefix announcement** — a more specific prefix (e.g. /25 inside a /24) appears from an unexpected AS. Classic hijack vector.

**AS path length spike** — sudden increase in path length for a stable prefix, indicating prepend attacks or route instability.

**New transit AS** — an AS not historically seen in the path for a prefix starts appearing as a transit hop.

Isolation Forest runs over a feature vector (origin AS, path length, path entropy, prefix length, new AS count) built per UPDATE message. NetworkX maintains the live AS topology graph — structurally anomalous paths (disconnected from known topology) get flagged independently of the statistical model.

---

## Data Sources

- **RIPE RIS Live** — WebSocket stream of real-time BGP updates from RIPE's Route Information Service. Free, no auth.
- **BGPStream (CAIDA)** — Provides both live feeds and historical MRT dumps. Used to train and validate the anomaly model against confirmed past hijack events.

---

## Running it

```bash
git clone https://github.com/arhansapra/bgpwatch
cd bgpwatch
docker compose up
```

Ingestor starts consuming the RIPE RIS Live feed immediately. Grafana dashboard available at `localhost:3000`. FastAPI docs at `localhost:8000/docs`.

---

## Project Structure

```
bgpwatch/
├── ingestor/        # WebSocket BGP feed consumer, Kafka producer
├── detector/        # Isolation Forest + NetworkX anomaly detection, Kafka consumer
├── state/           # Routing baseline manager, PostgreSQL + Redis writer
├── api/             # FastAPI query layer
├── metrics/         # Prometheus exporter
├── docker-compose.yml
└── README.md
```