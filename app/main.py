from fastapi import FastAPI

from .routes import router


app = FastAPI(
    title="DependencyRisk API",
    description=(
        "Automated open-source dependency "
        "security intelligence for software agents."
    ),
    version="0.1.0"
)


@app.get("/")
async def root():
    return {
        "name": "DependencyRisk API",
        "version": "0.1.0",
        "status": "online"
    }


@app.get("/health")
async def health():
    return {
        "status": "healthy"
    }


app.include_router(router)
