from fastapi import FastAPI

from routes import router
from workers import asgi

from x402.http import (
    HTTPFacilitatorClient,
    FacilitatorConfig,
    PaymentOption,
)
from x402.http.middleware.fastapi import PaymentMiddlewareASGI
from x402.http.types import RouteConfig
from x402.server import x402ResourceServer
from x402.mechanisms.evm.exact import ExactEvmServerScheme


app = FastAPI(
    title="DependencyRisk API",
    description="Automated open-source dependency security intelligence for software agents.",
    version="0.1.0"
)


# --------------------------------------------------
# x402 PAYMENT CONFIGURATION
# --------------------------------------------------

PAY_TO = "0x74d967874bc82f62321edFca05aE1662a65F31d8"

NETWORK = "eip155:84532"  # Base Sepolia testnet

FACILITATOR_URL = "https://x402.org/facilitator"


facilitator = HTTPFacilitatorClient(
    FacilitatorConfig(
        url=FACILITATOR_URL
    )
)


payment_server = x402ResourceServer(facilitator)

payment_server.register(
    NETWORK,
    ExactEvmServerScheme()
)


payment_routes = {
    "GET /check-package": RouteConfig(
        accepts=[
            PaymentOption(
                scheme="exact",
                price="$0.01",
                network=NETWORK,
                pay_to=PAY_TO,
            )
        ],
        description="Check a package version for known security vulnerabilities.",
        mime_type="application/json",
    ),
}


app.add_middleware(
    PaymentMiddlewareASGI,
    routes=payment_routes,
    server=payment_server,
)


# --------------------------------------------------
# FREE ENDPOINTS
# --------------------------------------------------

@app.get("/")
async def root():
    return {
        "name": "DependencyRisk API",
        "version": "0.1.0",
        "status": "online",
        "service": "dependency-security-intelligence"
    }


@app.get("/health")
async def health():
    return {
        "status": "healthy"
    }


# --------------------------------------------------
# API ROUTES
# --------------------------------------------------

app.include_router(router)


# --------------------------------------------------
# CLOUDFLARE PYTHON WORKER
# --------------------------------------------------

Default = asgi.entrypoint(app)
