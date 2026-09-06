# NetraX Frontend

React/Vite dashboard for the NetraX analysis API.

## Requirements

- Node.js 20+
- NetraX FastAPI backend running on port `8000` by default

## Install

```bash
npm install
```

## Run

```bash
npm run dev
```

The frontend sends uploaded `.pcap`, `.pcapng`, and `.csv` files to `POST /api/analyze`.

Set `VITE_API_BASE_URL` if the backend is not available at `http://<current-host>:8000`.

## Checks

```bash
npm run build
npm run lint
```
