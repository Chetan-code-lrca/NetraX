# NetraX Frontend

React/Vite dashboard for the NetraX FastAPI service.

## Run locally

Clone the repository and move into the project:

```bash
git clone https://github.com/Chetan-code-lrca/NetraX.git
cd NetraX
```

Start the API in one terminal:

```bash
PYTHONPATH=. python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```

Start the dashboard in another terminal:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`.

The Vite development server proxies `/api/*` to the local API at `http://127.0.0.1:8000`.

## Uploads

The dashboard accepts the traffic files supported by the NetraX API. CSV files must already contain the flow features expected by the backend. PCAP and PCAPNG files are converted to flow data by the backend before analysis.

## Vercel deployment

Deploy the `frontend` directory as a Vite application and set:

```text
VITE_NETRAX_API_URL=<address of your deployed NetraX API>
```

The variable is used as the base URL for API requests when the dashboard and backend are deployed separately.
