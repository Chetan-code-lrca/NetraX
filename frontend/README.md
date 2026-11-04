# NetraX Dashboard

The React/Vite frontend for the NetraX passive traffic-analysis application.

## Recommended run mode

For the complete product, follow the root
[README](../README.md) and run the API and dashboard together with Docker
Compose:

```bash
docker compose up --build
```

Open **http://localhost:8080**.

## Frontend-only development

Start the FastAPI backend from the repository root:

```bash
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```

In another terminal:

```bash
cd frontend
npm ci
npm run dev
```

Open **http://localhost:5173**. Vite proxies `/api/*` to the local API at
`http://127.0.0.1:8000`.

For a separately deployed frontend, set `VITE_NETRAX_API_URL` at build time
to the API base URL. Configure that frontend's origin in
`NETRAX_ALLOWED_ORIGINS` on the backend.

## Scripts

- `npm run dev` — start the development server
- `npm run build` — create the production build
- `npm run preview` — preview the production build locally

The dashboard uploads files to the backend; it does not capture packets or
run inference in the browser. It can export a completed analysis as JSON.
