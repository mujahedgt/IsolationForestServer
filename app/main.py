from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import db
from app.routes import analyze, training, audit, labeling, statistics
import uvicorn

# ------------------------------------------------------------------
# FastAPI Application Instance
# ------------------------------------------------------------------
app = FastAPI(
    title="IsolationForestServer",
    description="ML-based anomaly detection service for intelligent request routing (Honeypot/Real System)",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# ------------------------------------------------------------------
# CORS Middleware (adjust in production!)
# ------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # In production: replace with actual frontend domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------------
# Lifecycle Events
# ------------------------------------------------------------------
@app.on_event("startup")
async def startup_event():
    db.connect()
    print("IsolationForestServer started successfully")

@app.on_event("shutdown")
async def shutdown_event():
    db.disconnect()
    print("IsolationForestServer shut down gracefully")

# ------------------------------------------------------------------
# Include Route Modules
# ------------------------------------------------------------------
app.include_router(analyze.router,      tags=["Analysis"])
app.include_router(training.router,     tags=["Training"])
app.include_router(audit.router,        tags=["Audit"])
app.include_router(labeling.router,     tags=["Labeling"])
app.include_router(statistics.router,   tags=["Statistics"])

# ------------------------------------------------------------------
# Health Check / Root Endpoint
# ------------------------------------------------------------------
@app.get("/", tags=["Health"])
async def root():
    return {
        "service": "IsolationForestServer",
        "status": "running",
        "version": "1.0.0",
        "documentation": "/docs"
    }

# ------------------------------------------------------------------
# Run server when executed directly
# ------------------------------------------------------------------
if __name__ == "__main__":
    from app.config import settings

    uvicorn.run(
        "app.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.API_RELOAD,
        log_level="info"
    )