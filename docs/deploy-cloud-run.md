# Deploying to Google Cloud Run

The image in this repo runs the HTTP API (`POST /triage`, `GET /healthz`) and listens
on `$PORT`, which is what Cloud Run expects. Deploying is optional: everything also
runs locally.

## 1. One-time setup

```bash
PROJECT_ID=your-project
REGION=us-central1
gcloud config set project $PROJECT_ID
gcloud services enable run.googleapis.com cloudbuild.googleapis.com \
    artifactregistry.googleapis.com secretmanager.googleapis.com
```

Store the Gemini API key in Secret Manager. The key never goes into the image or the repo.

```bash
printf '%s' "$GOOGLE_API_KEY" | gcloud secrets create GOOGLE_API_KEY --data-file=-
PROJECT_NUMBER=$(gcloud projects describe $PROJECT_ID --format='value(projectNumber)')
gcloud secrets add-iam-policy-binding GOOGLE_API_KEY \
    --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
    --role=roles/secretmanager.secretAccessor
```

## 2. Deploy from source

Cloud Build builds the Dockerfile, and Cloud Run runs it:

```bash
gcloud run deploy triage-agents \
    --source . \
    --region $REGION \
    --no-allow-unauthenticated \
    --set-secrets GOOGLE_API_KEY=GOOGLE_API_KEY:latest \
    --set-env-vars TRIAGE_MODEL=gemini-3.5-flash-lite \
    --memory 1Gi --cpu 1 \
    --min-instances 0 --max-instances 1 \
    --concurrency 4 --timeout 300
```

Why these flags:

- `--no-allow-unauthenticated`: the service is private. Callers need IAM
  `roles/run.invoker`. A triage endpoint that ingests security data shouldn't be public.
- `--max-instances 1`: the rate limiter is in-process, and the Gemini quota is per project.
  One instance means one shared budget. To scale out, move the limiter to a shared store
  (for example Memorystore/Redis) or use a paid tier with higher limits.
- `--min-instances 0`: scale to zero when idle, so cost tracks usage.
- `--timeout 300`: a triage takes roughly 10 s to 2 min, depending on how much of the time
  is free-tier rate-limit waiting.

## 3. Call it

```bash
URL=$(gcloud run services describe triage-agents --region $REGION --format='value(status.url)')
TOKEN=$(gcloud auth print-identity-token)
curl -s -H "Authorization: Bearer $TOKEN" "$URL/healthz"
curl -s -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d @eval/alerts/EVAL-02.json "$URL/triage" | jq '.report.severity, .metrics.model_calls'
```

## 4. Observability on Google Cloud

- **Our trace plugin.** `POST /triage?include_trace=true` returns the per-step trace: which
  agent did what, in order, with tokens and timing.
- **ADK's OpenTelemetry spans.** ADK emits spans (`invoke_agent`, `execute_tool`,
  `generate_content`) that can be exported to Cloud Trace. Set `OTEL_SERVICE_NAME`, and
  configure the GCP exporter as described in ADK's observability docs.
- **Logs.** Cloud Run collects stdout and stderr in Cloud Logging automatically.

## Alternative: `adk deploy cloud_run`

ADK's CLI can also deploy the agent with its dev UI (`--with_ui`), which is handy for demos:

```bash
uv run adk deploy cloud_run --project $PROJECT_ID --region $REGION --with_ui .
```

This repo uses its own FastAPI app instead, to control the API contract and the input
validation and size limits, and to return reports, metrics and traces in one response.
