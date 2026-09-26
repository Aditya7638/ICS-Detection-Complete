<div align="center">

# ICS Detection & Monitoring

An experimental ICS/SCADA security monitoring platform that classifies sensor readings with a Random Forest model and process rules, then presents detections, alarms, and investigation context in a live dashboard.

[Features](#features) · [Quick Start](#quick-start) · [Configuration](#configuration) · [API](#api-overview) · [Safety](#safety-and-limitations)

</div>

> **Important:** This is a research/demo system, not a safety system or a certified industrial intrusion detection product. It does not connect to or control PLCs or plant equipment.

## What It Does

- Accepts sensor rows and CSV datasets for inference.
- Validates expected sensor fields and computes temporal features for the included classifier.
- Combines model output with the configured process-rule engine and labels results `Normal`, `Suspicious`, or `Attack`.
- Persists user-scoped detections and related alarms; streams live simulator events over WebSocket.
- Provides dashboard, live monitor, alarm center, analytics, and an optional AI chat assistant.
- Replays the configured CSV repeatedly until stopped. Replay is simulated data, not a live plant connection.

## Detection Flow

```text
Sensor row / CSV
      |
      v
Validation -> temporal features -> Random Forest probability
                                      |
                         process-rule engine
                                      |
                                      v
                               fusion result
                                      |
               Normal / Suspicious / Attack + alarm
                                      |
                        database + dashboard / WS
```

The bundled model expects 168 features: 42 raw sensor values and three derived features per sensor (`roll_mean5`, `roll_std5`, and `diff5`). Batch processing and simulator replay carry recent row history into inference. The model classifies provided readings; it does not predict future plant states. The fusion threshold and active rules are defined in the repository configuration and rule implementation.

## Tech Stack

- **Backend:** Python, FastAPI, SQLAlchemy, Pydantic, pandas, scikit-learn, JWT
- **Database:** PostgreSQL by default; SQLite can be used for local development
- **Frontend:** React, TypeScript, Vite, Tailwind CSS, Recharts
- **Optional AI:** Groq or OpenAI API, configured with an API key

## Repository Layout

```text
backend/
  app/                  FastAPI routes, auth, database, detection and services
  ml_models/            Pre-trained classifier
  config/               Fusion configuration
  rules/                Active and candidate detection rules
  requirements.txt
  .env.example
frontend/
  src/                  React pages, components, hooks and API client
data/
  ne_data.csv           Default simulator dataset
```

## Quick Start

### Requirements

- Python 3.11 or newer
- Node.js and npm
- PostgreSQL, or SQLite for local development

Open two PowerShell terminals from the repository root.

### 1. Configure the backend

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `backend/.env` before starting the app. Set a private, random `JWT_SECRET` and a valid database URL. The example uses PostgreSQL; for a local SQLite database, set:

```env
DATABASE_URL=sqlite:///./ics_dev.db
```

The app creates tables at startup for development. Alembic configuration is included for database migrations; use migrations as part of a production deployment process.

Start the API from the `backend` directory:

```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Interactive API documentation: <http://127.0.0.1:8000/docs>

### 2. Start the frontend

In a second terminal, from the repository root:

```powershell
cd frontend
npm install
Copy-Item .env.example .env
npm run dev
```

Open <http://localhost:5173>. Vite proxies `/api` requests to the backend on port `8000` by default.

Register an account through the app, then sign in. Do not use real operational credentials or secrets in a development environment.

## Configuration

Backend settings are loaded from `backend/.env` when Uvicorn is started from the `backend` directory.

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | SQLAlchemy database connection URL |
| `JWT_SECRET` | Secret used to sign authentication tokens; replace the example value |
| `JWT_EXPIRE_MINUTES` | Token lifetime in minutes |
| `MODEL_PATH` | Model path relative to `backend/` |
| `FUSION_CONFIG_PATH` | Fusion configuration path relative to `backend/` |
| `SIMULATOR_DATASET` | CSV path used by the replay simulator; defaults to `data/ne_data.csv` |
| `LLM_PROVIDER` | `groq` or `openai` |
| `LLM_API_KEY` | Optional provider API key; keep it private and out of Git |
| `LLM_MODEL` | Model name sent to the selected provider |
| `CORS_ORIGINS` | Comma-separated allowed frontend origins |

Frontend settings are in `frontend/.env.example`. `VITE_API_BASE_URL` defaults to `/api/v1`; the Vite development proxy targets `http://127.0.0.1:8000`.

## Using the Simulator

The default dataset is `data/ne_data.csv`, included in this repository. Start, pause/resume, and stop replay from the **Live Monitor**. Replay cycles through the CSV until stopped and sends each row through the detection pipeline. It is explicitly demo/replay mode and does not represent a real-time plant sensor connection.

The Live Monitor also lets you filter and select persisted detections individually or in groups for deletion. Deletion is permanent and removes associated alarms; only records belonging to the signed-in user are eligible. CSV rows displayed only as upload previews are not persisted selectors.

## API Overview

All REST endpoints use the `/api/v1` prefix and require a bearer token unless noted. The full schema is available at `/docs`.

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/auth/register` | Create an account |
| `POST` | `/auth/login` | Obtain a JWT |
| `GET` | `/auth/me` | Current account |
| `GET` | `/health` | Health status |
| `GET` | `/system/model-info` | Model metadata |
| `POST` | `/inference/row` | Classify one sensor row; optional `history` array of up to five preceding rows |
| `POST` | `/inference/csv` | Analyze a CSV upload |
| `POST` | `/inference/csv/stream` | Analyze CSV and return newline-delimited result batches |
| `GET` | `/monitoring/latest` | Latest persisted detections |
| `GET` | `/monitoring/history` | Paginated detection history |
| `DELETE` | `/monitoring/history` | Delete selected detection IDs and linked alarms |
| `GET` | `/alarms` | List alarms, optionally filtered by severity or status |
| `POST` | `/alarms/{id}/acknowledge` | Acknowledge an alarm |
| `POST` | `/alarms/{id}/resolve` | Resolve or mark as false positive |
| `GET` | `/analytics/overview` | Detection and alarm summary |
| `GET` | `/analytics/recent` | Recent predictions |
| `POST` | `/chat` | Chat or request detection analysis |
| `POST` | `/simulator/start` | Start dataset replay |
| `POST` | `/simulator/pause` | Toggle pause/resume |
| `POST` | `/simulator/stop` | Stop replay |
| `GET` | `/simulator/status` | Replay status |
| `WS` | `/ws/monitor` | Live detection stream |

Example row request (include all required sensor fields for the configured model):

```json
{
  "FIT101": 0.0,
  "history": []
}
```

The example is illustrative only; the validator requires the complete set of expected sensor columns. Check the model metadata and `/docs` for request schemas.

## Optional AI Assistant

The assistant can respond to general conversation or analyze supplied detection context. For provider-backed replies, set `LLM_PROVIDER`, `LLM_API_KEY`, and `LLM_MODEL` in `backend/.env`. Without a key, the API uses a limited fallback response.

AI output is advisory, may be inaccurate, and must be checked against approved incident-response procedures. Do not provide the assistant with secrets, sensitive plant details, or data that you are not authorized to share with the configured provider.

## Development Checks

From the repository root:

```powershell
Push-Location backend
.\.venv\Scripts\python.exe -m compileall app
Pop-Location

Push-Location frontend
npm run build
Pop-Location
```

## Safety and Limitations

- This software is for research and demonstration. It is not validated or certified for operational decisions.
- Classifications and rules can produce false positives and false negatives. Do not treat a model probability as proof of an attack.
- Dataset replay and offline CSV inference are not live plant monitoring.
- The assistant cannot replace authorized operators, formal incident response, or independent verification.
- Never use this application to issue PLC commands, change actuator states, suppress alarms, or control industrial processes.
- Keep `.env` files and API keys private. If a key is committed or shared, revoke it at the provider and replace it.
4. WebSocket authentication uses a query param token (`?token=...`). For production, use a proper WSS connection with header-based auth.
#   I C S - D e t e c t i o n 
 
 