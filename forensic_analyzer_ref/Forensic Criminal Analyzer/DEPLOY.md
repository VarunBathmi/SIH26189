# Deploying Forensic Criminal Analyzer

This app is deployment-ready two ways: **free-tier hosting** (best for a
hackathon — a real public URL, zero cost) or **Docker** (best for a local
one-command demo on your laptop, no internet dependency). Both are tested
and confirmed working — gunicorn serves the API correctly, and the frontend
correctly bakes in a production API URL at build time.

## Option A — Free hosting (Render + Vercel), ~10 minutes

### 1. Push this project to a GitHub repo
```bash
git init
git add .
git commit -m "Forensic Criminal Analyzer"
git remote add origin <your-repo-url>
git push -u origin main
```

### 2. Deploy the backend on Render.com (free tier)
1. Go to [render.com](https://render.com) → New → Blueprint
2. Connect your GitHub repo — Render will detect `render.yaml` automatically
   and configure everything (root dir `backend`, build command, start command)
3. Click **Apply** — Render builds and gives you a URL like
   `https://forensic-criminal-analyzer-api.onrender.com`
4. Confirm it's live: visit `https://<your-render-url>/api/health` → should
   return `{"status": "ok"}`

   *No `render.yaml`/Blueprint option showing? Deploy manually instead:*
   *New → Web Service → point at your repo → Root Directory: `backend` →*
   *Build Command: `pip install -r requirements.txt` → Start Command:*
   *`gunicorn --bind 0.0.0.0:$PORT wsgi:app`.*

### 3. Deploy the frontend on Vercel (free tier)
1. Go to [vercel.com](https://vercel.com) → New Project → import the same repo
2. Set **Root Directory** to `frontend`
3. Add an environment variable:
   `VITE_API_URL` = `https://<your-render-backend-url>/api`
4. Deploy — Vercel gives you a URL like
   `https://forensic-criminal-analyzer.vercel.app`

### 4. Lock down CORS (optional but recommended)
Back in Render, set the backend's `ALLOWED_ORIGINS` env var to your exact
Vercel URL instead of `*`, e.g.
`ALLOWED_ORIGINS=https://forensic-criminal-analyzer.vercel.app`, then redeploy.

**That's it — your Vercel URL is the working, shareable link.**

Note: Render's free tier spins down after inactivity, so the first request
after idling takes ~30-50s to wake up. For a live hackathon demo, open the
app a minute or two before you present so it's already warm.

---

## Option B — Docker (local, one command)

Requires Docker Desktop installed on your machine.

```bash
docker compose up --build
```

- Frontend: http://localhost:8080
- Backend API: http://localhost:5000/api/health

This runs both services together with nginx proxying `/api` to the Flask
backend — no environment variables to configure, works fully offline.

---

## Option C — Run without Docker (what we tested directly)

**Backend** (production server, not the Flask dev server):
```bash
cd backend
pip install -r requirements.txt
gunicorn --bind 0.0.0.0:5000 wsgi:app
```

**Frontend**:
```bash
cd frontend
npm install
npm run build
npx serve dist -p 8080
```
Set `VITE_API_URL` before `npm run build` if the backend isn't on the same
host — see `frontend/.env.example`.

---

## What's already wired for production

- `wsgi.py` + gunicorn — the Flask dev server (`run.py`) is fine for local
  testing but was never meant to be the production entry point
- CORS reads `ALLOWED_ORIGINS` from an env var instead of allowing everything
  by default in production
- Frontend reads `VITE_API_URL` at build time so it isn't hard-wired to
  `localhost` — confirmed the built JS bundle correctly contains the
  configured URL
- `render.yaml` blueprint so Render auto-configures the backend from the repo
- `docker-compose.yml` + Dockerfiles for both services for a fully
  self-contained local deployment
