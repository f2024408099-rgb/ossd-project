import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse

from routers import users, incidents, admin
from database import seed_database

app = FastAPI(
    title="CyberTrace Threat Intelligence",
    description="Collaborative Threat Intelligence & Incident Reporting Platform",
    version="1.0.0"
)

# CORS setup for developer local sandboxing & external requests API validation
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register backend package routers
app.include_router(users.router)
app.include_router(incidents.router)
app.include_router(admin.router)

@app.on_event("startup")
async def startup_event():
    print("Initializing CyberTrace database seeding routines...")
    try:
        await seed_database()
        print("Database seeded or verified successfully.")
    except Exception as e:
        print(f"Error during database startup seeding: {e}")

@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "CyberTrace Engine"}

# Serve specific pages directly on root paths for friendly UX
@app.get("/")
async def root():
    return FileResponse("static/index.html")

# Serve other pages nicely if accessed at clean path names
@app.get("/login")
async def login_page():
    return FileResponse("static/login.html")

@app.get("/register")
async def register_page():
    return FileResponse("static/register.html")

@app.get("/dashboard")
async def dashboard_page():
    return FileResponse("static/dashboard.html")

@app.get("/feed")
async def feed_page():
    return FileResponse("static/feed.html")

@app.get("/incident")
async def incident_detail_page():
    return FileResponse("static/incident_detail.html")

@app.get("/profile")
async def profile_page():
    return FileResponse("static/profile.html")

@app.get("/admin")
async def admin_page():
    return FileResponse("static/admin.html")

# Mount general static assets directory (HTML, CSS, JS) at /static
app.mount("/static", StaticFiles(directory="static"), name="static")

# Mount root static files fallback (serves files like /style.css, /app.js, and page-level HTML fallbacks)
app.mount("/", StaticFiles(directory="static"), name="root_static")

