# EnCodeLab Backend

Flask API that powers the EnCodeLab crypto lab: encryption, decryption, key/nonce generation, and benchmarks.

## Run locally
Prerequisites: Python 3.10+.

```bash
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
```

Server: `http://localhost:5000`

## Quick API
- `GET /` health + supported algorithms
- `POST /encrypt` encrypt data
- `POST /decrypt` decrypt data
- `POST /generate` key/nonce helper
- `POST /benchmark` performance benchmark

See the frontend for the full interactive experience.
