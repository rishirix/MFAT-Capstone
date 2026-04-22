# MFAT — Memory Forensics Automated Tool

Automated malware detection from Windows memory dumps using Volatility + Docker + Jenkins.

## Project Structure

```
MFAT/
├── preprocessing/
│   ├── runner.py        ← Runs Volatility plugins via Docker
│   └── parser.py        ← Parses raw output into structured data
├── backend/
│   ├── app.py           ← Flask API server
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   └── dashboard.html   ← Web dashboard UI
├── volatility2/
│   └── Dockerfile       ← Volatility 2.x image
├── volatility3/
│   └── Dockerfile       ← Volatility 3.x image
├── docker-compose.yml
└── Jenkinsfile
```

## Input

You provide a **memory dump file** (.raw, .vmem, .mem, .dmp).
This is a raw binary snapshot of a Windows machine's RAM — Volatility reads it directly.

## How to Run (Development / Testing)

### Step 1 — Start Docker Desktop (Windows only)
Open Docker Desktop from Start Menu. Wait for the whale icon in taskbar to stop animating.

### Step 2 — Build Volatility images

```bash
docker build -t vol2 ./volatility2
docker build -t vol3 ./volatility3
```

### Step 3 — Start the backend

```bash
cd backend
pip install -r requirements.txt
python app.py
```

### Step 4 — Open the dashboard

Open http://localhost:5000 in your browser.

### Step 5 — Upload a memory dump

Drag and drop your .raw file onto the dashboard and click "Initiate Scan".

---

## How to Run with Docker Compose (Production)

```bash
# Build all images first
docker build -t vol2 ./volatility2
docker build -t vol3 ./volatility3

# Start the backend
docker compose up --build backend
```

Open http://localhost:5000

---

## Jenkins Setup

1. Run Jenkins with Docker socket access:
```bash
docker run -d \
  -p 8080:8080 \
  -v jenkins_home:/var/jenkins_home \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --name jenkins \
  jenkins/jenkins:lts
```

2. Open http://localhost:8080
3. Create a new Pipeline job
4. Point it at this repo
5. Set Script Path to `Jenkinsfile`

---

## Testing with a Free Memory Dump

Download from: https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples
or CTF challenges from: https://github.com/stuxnet999/MemLabs

---
