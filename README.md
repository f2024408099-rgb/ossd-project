# CyberTrace — Collaborative Threat Intelligence & Incident Reporting Platform

Welcome to **CyberTrace**, a robust, secure cyber threat incident intelligence catalog and analysis board. 

## Features
- **Anonymous & Member Contributions**: Submission feeds for phishing sites, malware hashes, rogue IPs, and malicious domain names.
- **22+ FastAPI Backend Endpoints**: Full CRUD, validation schemas, token authentication, and platform analytics telemetry.
- **Dual-Mode Persistence**: Transparently connects to MongoDB Atlas or falls back to an high-performance local memory cluster.
- **Admin Command Slate**: Verifying submissions, user auditing, and real-time incident review workflow trackers.

## Folder Blueprint
```
CyberTrace/
├── main.py            # FastAPI Entry Point
├── models.py          # Pydantic Schemas & Payloads
├── database.py        # MongoDB Client Connection Manager
├── auth.py            # JWT Encryption & Security Guards
├── routers/           # Subsystem API Packages
│   ├── incidents.py   # Incident Logs, COMMENTS, and Lookup Controllers
│   ├── users.py       # Authentication & Registration Engine
│   └── admin.py       # verification approvals & analytics trackers
├── static/            # Native HTML UI Pages
│   ├── index.html     # Welcome Landing Slate
│   ├── login.html     # Sign In Form
│   ├── register.html  # Register Profile Forms
│   ├── dashboard.html # Submission & Contribution Log
│   ├── feed.html      # Public Search & Filter Catalogs
│   ├── incident_detail.html # comments discussion hub
│   ├── profile.html   # User Profile Panel
│   ├── admin.html     # Security Operations Center Panel
│   └── style.css      # Cohesive Branding CSS stylesheet
```

## Setup & Running Local
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Configure settings in `.env` (derived from `.env.example`).
3. Run the ASGI server:
   ```bash
   uvicorn main:app --reload --port 3000
   ```
4. Access the Swagger endpoint directly on `http://localhost:3000/docs` to review documentation.
