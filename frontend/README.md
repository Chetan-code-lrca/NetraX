# NetraX Frontend

Production-ready React/Vite dashboard for the NetraX FastAPI service.

## Local

Run the backend:

```bash
cd ~/NetraX
PYTHONPATH=. python -m uvicorn api.main:app --host 0.0.0.0 --port 8000
```

Run the frontend:

```bash
cd ~/NetraX/frontend
npm install
npm run dev
```

Open `http://localhost:5173`.

The Vite proxy forwards `/api/*` to `http://127.0.0.1:8000`.

CSV uploads must already contain NetraX-compatible flow features. PCAP/PCAPNG uploads are converted by the backend.

## Vercel

Set:

```text
VITE_NETRAX_API_URL=https://YOUR-PUBLIC-NETRAX-API
```

and deploy this directory.
