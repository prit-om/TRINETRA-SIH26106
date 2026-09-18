# TRINETRA— Frontend

Professional React/Vite analyst dashboard for **SIH26106 — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform**.

## Run

```bash
npm install
npm run dev
```

The backend defaults to `http://localhost:8000`. Override it with:

```env
VITE_API_BASE_URL=http://localhost:8000
```

## Backend contract used

- `GET /health`
- `POST /analyze` — multipart `raw_text` or `file`
- `GET /cases`
- `GET /cases/{case_id}`
- `GET /cases/{case_id}/report.pdf`
- `GET /alerts`
- `GET /monitor/status`
- `POST /monitor/start`
- `POST /monitor/stop`

The frontend keeps external API keys out of the browser.

## Investigation view

The Analysis View presents risk and classification, SPF/DKIM/DMARC, NLP behavior signals, URL and attachment findings, the three-layer Evidence Package, SMTP relay trace, approximate sender infrastructure geolocation with an OpenStreetMap mini-map, IOC/campaign relationship graph, attribution-support confidence, evidence integrity, and PDF reporting.

Geolocation is explicitly presented as **probable source infrastructure**, not the physical location or identity of a person. Attribution confidence is evidence-weighted and not proof of actor identity.
