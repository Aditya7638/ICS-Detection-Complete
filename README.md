# ICS Detection System

A machine-learning and rule-based intrusion detection system for Industrial Control Systems (ICS). The system combines a trained Random Forest classifier with process-aware security rules and a fusion layer to detect potentially malicious or anomalous industrial process activity.

The project provides a FastAPI backend for inference and a frontend interface for interacting with the detection system.

## Features

* Machine-learning-based ICS attack detection
* Random Forest classification model
* Process-aware rule engine
* ML + rule-based decision fusion
* Configurable fusion strategy and detection threshold
* Feature-based inference using industrial process data
* FastAPI backend
* Frontend interface
* Structured request validation using Pydantic
* Model and configuration separation
* Detection results with ML/rule evidence
* Configurable security rules
* Support for future company-specific detector customization

## System Architecture

```text
                    ICS Sensor / Process Data
                              │
                              ▼
                    ┌──────────────────┐
                    │  Feature Input   │
                    │   & Validation   │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ Feature Processing│
                    └────────┬─────────┘
                             │
                  ┌──────────┴──────────┐
                  │                     │
                  ▼                     ▼
        ┌──────────────────┐   ┌──────────────────┐
        │ Random Forest    │   │   Rule Engine    │
        │   Classifier     │   │ Process-Aware    │
        └────────┬─────────┘   └────────┬─────────┘
                 │                      │
                 │ ML Evidence          │ Rule Evidence
                 └──────────┬───────────┘
                            ▼
                    ┌──────────────────┐
                    │  Fusion Engine   │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ Detection Result │
                    └────────┬─────────┘
                             │
                             ▼
                       FastAPI API
                             │
                             ▼
                         Frontend
```

## Project Structure

The exact structure can vary as the project evolves, but the main components are organized around the backend, frontend, model artifacts, rules, and configuration.

```text
ICS-Detection/
│
├── backend/
│   ├── ...
│   ├── .venv/
│   └── ...
│
├── frontend/
│   ├── ...
│   └── ...
│
├── best_model.joblib
├── fusion_config.json
├── rule_engine_final.py
├── candidate_rules.py
├── NewTestData.csv
├── .gitignore
└── README.md
```

> `.venv`, `.env`, dependencies, build output, and other local/generated files should not be committed to the repository.

## Core Components

### 1. Random Forest Model

The trained Random Forest model is used as the primary machine-learning-based detector.

The model receives the required processed feature vector and produces the ML prediction/probability used by the detection pipeline.

Model artifact:

```text
best_model.joblib
```

The model should always be used together with the feature-processing logic and feature schema with which it was trained.

### 2. Rule Engine

The rule engine provides process-aware detection logic in addition to the machine-learning model.

Important rule files include:

```text
rule_engine_final.py
candidate_rules.py
```

Rules can represent domain/process constraints that may not be captured completely by the statistical model.

This allows the system to use both:

* Data-driven ML evidence
* Process/domain-driven rule evidence

### 3. Fusion Layer

The fusion layer combines the ML prediction and rule-engine result.

Configuration is stored separately so that detection behavior can be adjusted without modifying the trained model itself.

Example configuration file:

```text
fusion_config.json
```

Depending on the configured strategy, the final decision can consider:

```text
ML prediction
+
Rule-engine evidence
+
Configured weights/thresholds
```

### 4. FastAPI Backend

The backend exposes the detection functionality through APIs.

The backend is responsible for:

1. Receiving input data
2. Validating the request
3. Processing the input features
4. Loading the trained model
5. Running ML inference
6. Executing the rule engine
7. Performing ML/rule fusion
8. Returning the final detection result

### 5. Frontend

The frontend provides the user interface for interacting with the detection system.

It communicates with the FastAPI backend and presents detection results to the user.

## Dataset

The project uses industrial process/sensor data containing the features required by the trained detection model.

An example test dataset is:

```text
NewTestData.csv
```

The model expects the same feature schema used during training.

**Important:** Changing the feature schema, adding new features, removing features, or changing feature engineering may require retraining the model.

## Detection Pipeline

The complete inference process is approximately:

```text
Input sensor/process data
        │
        ▼
Request validation
        │
        ▼
Feature processing
        │
        ├───────────────┐
        ▼               ▼
 Random Forest      Rule Engine
        │               │
        ▼               ▼
  ML prediction     Rule result
        │               │
        └───────┬───────┘
                ▼
           Fusion Layer
                │
                ▼
       Final Detection Result
```

## Configuration

Detection behavior that does not require changing the trained model can be controlled through configuration.

Typical configurable parameters include:

* ML decision threshold
* ML/rule weighting
* Fusion strategy
* Rule activation
* Rule priority/severity

For example, increasing the ML decision threshold can reduce the number of positive detections at the cost of potentially missing some attacks.

Configuration changes should always be evaluated on validation data before being used in production.

## Model Adaptation

The project is designed so that future customization can be implemented without changing the core FastAPI application.

There are three broad levels of adaptation.

### Level 1 — Configuration Adaptation

These generally do not require model retraining:

```text
Detection threshold
ML/rule weights
Fusion strategy
Rule priority
Rule activation
Operational sensor criticality
```

### Level 2 — Feature Adaptation

Changes such as:

```text
Adding sensors
Removing features
Changing feature engineering
Changing preprocessing
Changing the feature schema
```

can require retraining because the trained model expects a specific feature representation.

### Level 3 — Model Adaptation

Retraining is appropriate when:

```text
New training data becomes available
A new attack class is introduced
The industrial process is substantially different
The feature schema changes
Significant distribution/concept drift occurs
```

The system should not modify the internal feature importance of a trained Random Forest as a substitute for retraining.

## Future Requirement-Driven Customization

A planned extension of the system is a requirement-driven customization framework.

A company could provide requirements such as:

```text
- Keep false positives below 1%
- Maintain recall above 90%
- LIT101 is a critical sensor
- Prioritize sensor manipulation attacks
- Detection latency should remain below 20 ms
```

These requirements can be converted into a structured configuration:

```text
Natural-language requirements
            │
            ▼
     Requirement Parser
            │
            ▼
   Structured Requirements
            │
            ▼
  Requirement Validation
            │
       ┌────┴────┐
       ▼         ▼
  Configuration  Retraining
   Optimizer     Required
       │
       ▼
  Validated Company Profile
```

The current threshold optimizer searches candidate decision thresholds for RF-only and RF-plus-rules OR fusion. It applies configured minimum-recall, maximum-FPR, and minimum-precision bounds and ranks feasible candidates according to the selected profile. It does not retrain the model or optimize rule priorities, risk weights, latency, or critical-asset-specific thresholds.

### Using the frontend optimizer

1. Sign in as a `SECURITY_ANALYST` or `ADMIN` and open **Optimizer** in the sidebar. Other signed-in roles can view profiles and completed results but cannot change production configuration.
2. Create a profile, choose an objective (`BALANCED`, `HIGH_RECALL`, `LOW_FP`, or `CRITICAL_ASSET`), and optionally enter metric bounds as percentages.
3. Select the new profile, set the threshold range and step, and run the search. The default evaluation dataset is `data/NewTestData.csv`, falling back to `data/ne_data.csv`; provide a project-root-relative path to use a different labeled CSV. The CSV needs the model's sensor columns and a `Normal/Attack` label column.
4. Review feasibility and the held-out test metrics before activating. Evaluation uses a chronological 70/15/15 split: threshold selection uses the validation segment, and final metrics use the separate test segment. A run that fails its constraints cannot be activated.
5. Use **Restore baseline** to return to the preserved `0.70` threshold / OR-fusion configuration.

The optimizer evaluates the available dataset and does not change production detection while it runs. Authorized activation applies the selected threshold and fusion strategy to new detections without changing model weights. **RF only** ignores rule violations when assigning the final detection label; **OR** combines the RF threshold with rule violations. Restore baseline to roll back.

### Frontend feature coverage

The sidebar links to the main user-facing backend workflows:

* **Dashboard** — system health, detection overview, and active profile.
* **Live Monitor** — WebSocket detections, simulator controls, and CSV inference.
* **Event History** — filtered saved events, sensor/rule search, and event evidence.
* **Alarms** — acknowledge and resolve actions.
* **Analytics** — detection and alarm summaries.
* **Model Info** — model metadata and features.
* **Optimizer** — detection profiles, threshold evaluation, comparison, activation, and baseline restore.
* **AI Assistant** — chat endpoint.

Authentication is presented through the login and registration screens. Public registration creates `OPERATOR` accounts only; elevated roles must be provisioned by an administrator and cannot be selected in the registration request. Backend internals such as database models, feature processing, the rule engine, and WebSocket transport are services used by these workflows rather than standalone screens.

## Important Design Principle

The natural-language component should **not directly modify backend code or security logic**.

Instead:

```text
Natural Language
       ↓
Structured Requirements
       ↓
Validator
       ↓
Deterministic Optimizer
       ↓
Validated Configuration
       ↓
Detection System
```

This keeps the security-critical decision process deterministic, testable, and reproducible.

## Installation

### Backend

Open PowerShell and navigate to the project:

```powershell
cd D:\ics_full_project\ICS-Detection
```

Create/activate the backend virtual environment if required:

```powershell
cd backend
```

If the project uses the existing `uv` environment:

```powershell
.venv\Scripts\Activate.ps1
```

Install the backend dependencies according to the project's dependency file.

Then start the FastAPI backend using the project's configured startup command.

For a standard FastAPI setup, this may be:

```powershell
uvicorn main:app --reload
```

> Use the actual entry-point/module configured in the backend if it differs from `main.py`.

### Frontend

Open another PowerShell terminal:

```powershell
cd D:\ics_full_project\ICS-Detection\frontend
```

Install dependencies:

```powershell
npm install
```

Start the development server:

```powershell
npm run dev
```

The Vite development server will display the local frontend URL in the terminal.

## Environment Variables

Environment-specific secrets should be stored in `.env`.

Example:

```env
# Example only
DATABASE_URL=your_database_url
API_KEY=your_api_key
```

Do **not** commit `.env` to GitHub.

The repository's `.gitignore` should contain:

```gitignore
.env
```

A safe practice is to provide a `.env.example` containing variable names but not real credentials.

## Git Workflow

After making changes:

```powershell
git status
git add .
git commit -m "Describe your changes"
git push
```

Before committing, verify that sensitive files such as `.env` are not staged:

```powershell
git status
```

## Validation and Evaluation

The detector should be evaluated using data that was not used to tune the configuration.

Important metrics include:

* Accuracy
* Precision
* Recall
* F1-score
* False Positive Rate (FPR)
* False Negative Rate (FNR)
* Detection latency

For configuration optimization, the validation data should be used for selecting thresholds and fusion parameters.

The final test set should remain isolated for unbiased evaluation.

## Security Considerations

Because this system is intended for ICS/industrial-process security:

* Model artifacts should be versioned.
* Feature schemas should be versioned.
* Rule configurations should be versioned.
* Company-specific configurations should be validated before deployment.
* Secrets must not be committed to source control.
* Configuration changes should be tested before production deployment.
* An optimizer should never claim to satisfy requirements that its validation results do not support.
* Changes to the trained feature representation should trigger appropriate model validation/retraining.

## Current Scope

The current system focuses on combining:

```text
Machine Learning
        +
Process-Aware Rules
        +
Decision Fusion
        +
FastAPI Inference
        +
Frontend Interface
```

The requirement-driven adaptation and automated customization layer is intended as an extension of the existing detection framework.

## Future Work

Potential extensions include:

* Requirement-driven detector customization
* Natural-language requirement conversion
* Automated configuration optimization
* Company-specific detector profiles
* Sensor criticality modeling
* Attack-specific prioritization
* Model retraining pipeline
* Feature-selection experiments
* Temporal/generalization evaluation
* Drift detection
* Model and configuration versioning
* Explainable detection results
* Automated requirement-satisfaction evaluation

## Disclaimer

This project is a research/development system for ICS intrusion detection. Detection results should be validated against the target industrial environment and operational requirements before being used in a production safety or security system.
