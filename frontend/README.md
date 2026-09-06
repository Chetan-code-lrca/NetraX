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

## API configuration

The API base URL is controlled by the `VITE_NETRAX_API_URL` Vite environment
variable:

- **Development** (`npm run dev`): if `VITE_NETRAX_API_URL` is not set, the
  app falls back to `http://<current-host>:8000`, so it works out of the box
  against a locally running backend on `localhost`/`127.0.0.1`.
- **Production builds** (`npm run build`): the app **never** falls back to
  localhost. `VITE_NETRAX_API_URL` must be set at build time to the deployed
  FastAPI backend's public URL, for example:

  ```
  VITE_NETRAX_API_URL=https://your-netrax-api.example.com
  ```

  If it is missing, the app shows an "Analysis service unavailable:
  configuration missing" state instead of silently calling localhost.

On Vercel, set `VITE_NETRAX_API_URL` as a Project Environment Variable
(Production/Preview) pointing at the deployed backend, then redeploy.

The backend's CORS configuration allows `http://localhost*`/`http://127.0.0.1*`
during development and any `https://*.vercel.app` origin by default; extra
production origins can be added via the backend's `NETRAX_ALLOWED_ORIGINS`
(comma-separated) environment variable.

## Checks

```bash
npm run build
npm run lint
```
