# LogShield — RapidAPI starter

A small FastAPI service that detects and redacts PII and common credentials from logs, support tickets, and AI prompts.

## Endpoints

- `GET /health`
- `GET /v1/types`
- `POST /v1/detect`
- `POST /v1/redact`

The API returns positions and entity types, but it does not echo detected values in match metadata.

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate     # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/docs`.

## Try it

```bash
curl -X POST http://127.0.0.1:8000/v1/redact \
  -H 'Content-Type: application/json' \
  -d '{
    "text": "Email alex@example.com. Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
    "mode": "label"
  }'
```

Example response:

```json
{
  "total": 2,
  "counts": {
    "bearer_token": 1,
    "email": 1
  },
  "matches": [
    {"type": "email", "start": 6, "end": 22, "confidence": 0.98},
    {"type": "bearer_token", "start": 46, "end": 72, "confidence": 0.98}
  ],
  "redacted_text": "Email [EMAIL]. Authorization: Bearer [BEARER_TOKEN]"
}
```

## Test

```bash
pytest -q
```

## Run with Docker

```bash
docker build -t logshield-api .
docker run --rm -p 8000:8000 logshield-api
```

## Publish through RapidAPI

1. Deploy this container to a public HTTPS URL.
2. In RapidAPI Studio, create an API project and set the backend Base URL.
3. In the Gateway settings, copy the value RapidAPI will send in `X-RapidAPI-Proxy-Secret`.
4. Set that value as the deployment environment variable `RAPIDAPI_PROXY_SECRET` and redeploy. Calls to `/v1/*` without the correct header will then receive HTTP 403.
5. Set `PUBLIC_BASE_URL` to the deployed URL.
6. An import-ready `openapi.json` is already included. After changing `PUBLIC_BASE_URL` or the endpoints, regenerate it with:

   ```bash
   curl https://YOUR-DOMAIN/openapi.json -o openapi.json
   ```

7. Import `openapi.json` in RapidAPI's Definitions area, set the Base URL in Studio if the file does not contain your production server, test every endpoint through the marketplace console, add example responses, then configure plans.

## Sensible first pricing experiment

- Free: 100 calls/month
- Starter: $9/month for 5,000 calls
- Growth: $29/month for 50,000 calls
- Scale: $79/month for 250,000 calls

Treat these as experiments. Track conversion, error rate, p95 latency, and support requests, then revise.

## Before calling it production-ready

- Publish a privacy policy and terms of service.
- Make a clear no-payload-retention promise only when your hosting and logs actually meet it.
- Disable request-body logging everywhere in the stack.
- Add abuse monitoring and alerts.
- Add integration tests for every detector and false-positive regression tests.
- Decide which countries and credential formats you officially support. The starter intentionally detects only international phone candidates beginning with `+`.
