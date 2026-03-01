"""Security Hardening Configuration Platform – FastAPI Backend."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routers.rules import router as rules_router

app = FastAPI(
    title="CIS Hardening API",
    description="Backend for the Security Hardening Configuration Platform",
    version="1.0.0",
)

# CORS – allow the Vite dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(rules_router)


@app.get("/")
async def root():
    return {"status": "ok", "service": "CIS Hardening API"}
