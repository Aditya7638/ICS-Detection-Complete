# ICS Anomaly Detection & Monitoring Platform

A complete production-style ICS/SCADA cyberattack detection system based on the **SWaT (Secure Water Treatment)** dataset, using a trained RandomForest classifier fused with a 16-rule physical-process rule engine.

---

## Architecture

```
ICS Data (CSV / API / WebSocket)
         ↓
  Validation Engine (42 raw sensor columns checked)
         ↓
  Feature Preparation (rolling mean/std/diff over window=5 → 168 features)
         ↓
  RandomForestClassifier (best_model.joblib, threshold=0.70)
         ↓                    ↓
  ML Probability         Rule Engine (16 validated rules)
         ↓                    ↓
         └──────── Fusion (OR logic) ──────────┘
                        ↓
            Final Label: Normal / Suspicious / Attack
                        ↓
               Alarm Engine (cooldown, severity)
                        ↓
           PostgreSQL + WebSocket broadcast
                        ↓
         React Dashboard (live feed, alarms, analytics)
                        ↓
                  AI Chatbot (advisory only)
```

---

## Artifact Inspection Results

| Property | Value |
|---|---|
| Model type | RandomForestClassifier (sklearn 1.7.2) |
| n_estimators | 200 |
| Total features | **168** (42 raw + 126 rolling) |
| Raw sensor columns | 42 (FIT101 … P602) |
| Rolling features | roll_mean5, roll_std5, diff5 per column |
| Classes | 0 = Normal, 1 = Attack |
| No embedded scaler | Raw values → rolling features → model |
| predict_proba() | ✅ Yes |
| Decision threshold | **0.70** (from fusion_config.json) |
| Fusion logic | **OR**: Attack if (ML ≥ 0.70) OR (any rule violation) |
| Active rules | 16: R10, R11, R20b, R_NEW_01–06, 08–13, 15 |
| Validated Precision | 98.6% |
| Validated Recall | 91.6% |
| Validated F1 | 95.0% |
| False Positive Rate | 1.3% |

### Candidate Rules (NOT active)
`candidate_rules.py` contains 15 unvalidated rules (R_NEW_01–15). Only those also present in `rule_engine_final.py`'s `ACTIVE_RULES` list are used. R_NEW_07 and R_NEW_14 are excluded — they fired too frequently on normal data.

---

## Tech Stack

**Backend:** Python 3.11 · FastAPI · Uvicorn · Pydantic v2 · SQLAlchemy · PostgreSQL · Alembic · scikit-learn · pandas · JWT  
**Frontend:** React 18 · TypeScript · Vite · Tailwind CSS · Recharts · React Router · Axios  
**ML:** RandomForestClassifier (pre-trained, no retraining) · rule_engine_final.py (unmodified) · fusion_config.json (authoritative)

---

## Project Structure

```
ICS-Detection/
├── backend/
│   ├── app/
│   │   ├── api/routes/        auth, inference, alarms, analytics, monitoring, system, chat, simulator, ws
│   │   ├── auth/              security.py (JWT, bcrypt, RBAC)
│   │   ├── core/              config.py (pydantic-settings)
│   │   ├── db/                models.py, session.py
│   │   ├── detection/
│   │   │   ├── model_engine.py      ← loads best_model.joblib, computes rolling features
│   │   │   ├── rule_adapter.py      ← wraps rule_engine_final.py (no rewrite)
│   │   │   ├── fusion_engine.py     ← implements fusion_config.json OR logic
│   │   │   ├── detection_service.py ← single detect() used by ALL paths
│   │   │   └── validator.py         ← validates all 42 raw columns
│   │   ├── schemas/           schemas.py (Pydantic v2)
│   │   ├── services/          alarm_service.py
│   │   ├── websocket/         manager.py
│   │   └── main.py
│   ├── ml_models/best_model.joblib
│   ├── config/fusion_config.json
│   ├── rules/rule_engine_final.py, candidate_rules.py
│   ├── requirements.txt
│   ├── alembic.ini
│   └── .env.example
├── frontend/
│   └── src/
│       ├── pages/             Login, Dashboard, Live, Alarms, Analytics, ModelInfo, Chat
│       ├── layouts/           AppLayout.tsx (sidebar nav)
│       ├── hooks/             useAuth.tsx, useWebSocket.ts
│       └── services/          api.ts (single API client)
├── data/                      ← place NewTestData.csv here for simulator
└── README.md
```

---

## Quick Start (Windows PowerShell)

### Prerequisites
- Python 3.11+
- Node.js 18+
- PostgreSQL (or use SQLite for dev: see `.env.example`)

### Database Setup (PostgreSQL)
```powershell
psql -U postgres
CREATE USER ics_user WITH PASSWORD 'password';
CREATE DATABASE ics_detection OWNER ics_user;
\q
```

### Backend
```powershell
cd ICS-Detection\backend

python -m venv .venv
.\.venv\Scripts\Activate.ps1

pip install -r requirements.txt

# Copy and edit environment file
copy .env.example .env
# Edit .env: set DATABASE_URL, JWT_SECRET, and optionally LLM_API_KEY

# Run database migrations (PostgreSQL)
alembic upgrade head

# Start backend (auto-creates tables on first run)
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Create an account from the registration page and choose its role. Passwords must be at least 9 characters and contain a special character.

### Frontend
```powershell
cd ICS-Detection\frontend
npm install
npm run dev
```
Open: http://localhost:5173

### Swagger API Docs
http://127.0.0.1:8000/docs

---

## SQLite (No PostgreSQL — Dev Only)
Edit `.env`:
```env
DATABASE_URL=sqlite:///./ics_dev.db
```
No `alembic upgrade head` needed — tables are auto-created on startup.

---

## CSV Simulator
Place `NewTestData.csv` in `ICS-Detection/data/`.

In the Live Monitor page → Start Simulator (1x / 5x / 10x speed).

Every row passes through the **actual** detection pipeline (model → rules → fusion).  
Labeled as **⚠ REPLAY / DEMO MODE** in the UI.

Or via API:
```powershell
curl -X POST "http://localhost:8000/api/v1/simulator/start?speed=5" -H "Authorization: Bearer <token>"
```

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| POST | /api/v1/auth/register | Register user |
| POST | /api/v1/auth/login | Login (returns JWT) |
| GET | /api/v1/auth/me | Current user |
| GET | /api/v1/health | System health |
| GET | /api/v1/system/model-info | Model metadata |
| POST | /api/v1/inference/row | Detect single row (JSON) |
| POST | /api/v1/inference/csv | Batch CSV detection |
| GET | /api/v1/monitoring/latest | Recent detections |
| GET | /api/v1/monitoring/history | Paginated history |
| GET | /api/v1/alarms | List alarms (filterable) |
| GET | /api/v1/alarms/{id} | Alarm detail |
| POST | /api/v1/alarms/{id}/acknowledge | Acknowledge |
| POST | /api/v1/alarms/{id}/resolve | Resolve / mark FP |
| GET | /api/v1/analytics/overview | Stats summary |
| GET | /api/v1/analytics/recent | Recent predictions |
| GET | /api/v1/analytics/alarms | Alarm statistics |
| POST | /api/v1/chat | AI assistant |
| POST | /api/v1/simulator/start | Start CSV replay |
| POST | /api/v1/simulator/stop | Stop simulator |
| POST | /api/v1/simulator/pause | Pause/resume |
| GET | /api/v1/simulator/status | Simulator status |
| WS | /api/v1/ws/monitor | Live event stream |

---

## RBAC

| Action | ADMIN | SECURITY_ANALYST | OPERATOR |
|---|---|---|---|
| View dashboard / analytics | ✅ | ✅ | ✅ |
| Upload CSV / detect row | ✅ | ✅ | ✅ |
| Acknowledge alarms | ✅ | ✅ | ✅ |
| Resolve / mark false positive | ✅ | ✅ | ❌ |
| Manage users | ✅ | ❌ | ❌ |
| View model info | ✅ | ✅ | ✅ |
| AI chatbot | ✅ | ✅ | ✅ |

---

## ML Integration Detail

1. **Startup:** `init_model_engine()` loads `best_model.joblib` once via joblib. `feature_names_in_` extracted directly from the model.
2. **Inference:** Incoming 42-column dict → `compute_rolling_features()` computes `roll_mean5`, `roll_std5`, `diff5` for each column (min_periods=1, so single rows work) → 168-column DataFrame passed to `model.predict_proba()`.
3. **Threshold:** `P(Attack) ≥ 0.70` → ML prediction = Attack.
4. **No scaler:** Model was trained on raw values; no StandardScaler or MinMaxScaler is embedded or needed.

---

## False-Alarm Reduction

- **Fusion OR logic:** either ML or rules must trigger — reduces ML-only false positives
- **Suspicious zone:** 0.50 ≤ ML prob < 0.70 → "Suspicious" (not a full alarm)
- **Alarm cooldown:** duplicate alarms of same severity suppressed within 2-minute window
- **Analyst feedback:** any alarm can be marked False Positive, tracked in DB
- **Separation:** ML result, rule result, fusion result, and alarm suppression are kept as distinct stages

---

## Chatbot Safety

The AI assistant (Groq/OpenAI backend) is **advisory only**:
- ❌ Cannot control PLCs, actuators, or valves
- ❌ Cannot disable alarms
- ❌ Cannot execute system commands
- ✅ Explains detections and rule violations
- ✅ Suggests investigation steps
- ✅ Answers questions about historical alarms

Configure: set `LLM_API_KEY` and `LLM_PROVIDER=groq` (or `openai`) in `.env`.  
Without an API key, the chatbot returns a graceful fallback message.

---

## Tests Actually Executed

All executed in this session without a live PostgreSQL — using SQLite:

| # | Test | Result |
|---|---|---|
| 1 | Model loads (168 features, RandomForestClassifier) | ✅ PASS |
| 2 | predict_proba() returns [P(Normal), P(Attack)] | ✅ PASS |
| 3 | compute_rolling_features() produces correct 168 cols | ✅ PASS |
| 4 | Validator: valid row accepted | ✅ PASS |
| 5 | Validator: missing field (MISSING error code) | ✅ PASS |
| 6 | Validator: NaN value (NAN error code) | ✅ PASS |
| 7 | Validator: non-numeric string (INVALID_TYPE) | ✅ PASS |
| 8 | Rule engine: attack pattern → 9 violations | ✅ PASS |
| 9 | Rule engine: normal-ish pattern → 0 violations | ✅ PASS |
| 10 | Fusion: ML-only (p=0.85) → Attack, HIGH | ✅ PASS |
| 11 | Fusion: rule-only (p=0.40, 2 rules) → Attack, MEDIUM | ✅ PASS |
| 12 | Fusion: nothing → Normal | ✅ PASS |
| 13 | Fusion: borderline (p=0.55) → Suspicious | ✅ PASS |
| 14 | DetectionService end-to-end: Attack, 9 rules | ✅ PASS |
| 15 | Password hash + verify | ✅ PASS |
| 16 | JWT create + decode | ✅ PASS |
| 17 | DB: user seed and query | ✅ PASS |
| 18 | Alarm created after attack detection | ✅ PASS |
| 19 | Alarm acknowledged | ✅ PASS |
| 20 | False positive marked | ✅ PASS |
| 21 | Alarm resolved | ✅ PASS |
| 22 | Analytics count query | ✅ PASS |
| 23 | Frontend TypeScript build (npm run build) | ✅ PASS |

**Not tested (requires live service):**
- WebSocket real-time broadcast (requires running uvicorn + connected client)
- Simulator CSV replay (requires NewTestData.csv placed in data/)
- AI chatbot LLM response (requires LLM_API_KEY)
- PostgreSQL-specific Alembic migrations (tested with SQLite)
- Full HTTP API routes via FastAPI TestClient (requires pytest setup)

---

## Limitations

1. Rolling features for a single isolated row use `min_periods=1` — this means `roll_std5=0` and `roll_diff5=0` for the first row. For best accuracy, send rows in batches or use the CSV endpoint which computes rolling features across the full sequence.
2. The 16 mined rules were validated on a **single 20k-row SWaT sample** — they may be sample-specific. Re-validate on the full SWaT dataset before reporting final metrics.
3. The simulator requires `NewTestData.csv` placed in `ICS-Detection/data/`. The file is not included in this repo.
4. WebSocket authentication uses a query param token (`?token=...`). For production, use a proper WSS connection with header-based auth.
