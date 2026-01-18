# EnCodeLab

Practical crypto lab for encrypting, decrypting, and benchmarking modern ciphers in a clean web UI.

## Quickstart

### 1) Clone
```bash
git clone https://github.com/0xrishabhh/EnCodeLab.git
cd EnCodeLab
```

### 2) Backend
```bash
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
```

### 3) Frontend
```bash
cd frontend
npm install
npm run dev
```

Open:
- Backend: `http://localhost:5000`
- Frontend: `http://localhost:3000`

More details:
- `backend/README.md`
- `frontend/README.md`

## Deployment (Vercel + Render)

### Backend (Render)
- Root: `backend`
- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn -b 0.0.0.0:$PORT app:app`
- Env: `CORS_ORIGINS=https://<your-vercel-domain>`

### Frontend (Vercel)
- Root: `frontend`
- Build command: `npm run build`
- Output: `dist`
- Env: `VITE_API_BASE_URL=https://<your-render-service>.onrender.com`
