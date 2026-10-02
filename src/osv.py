import httpx


OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


async def query_package(package: str, ecosystem: str, version: str) -> dict:
    payload = {
        "package": {
            "name": package,
            "ecosystem": ecosystem
        },
        "version": version
    }

    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.post(
            OSV_QUERY_URL,
            json=payload
        )

    response.raise_for_status()
    return response.json()


async def query_batch(dependencies: list[dict]) -> list[dict]:
    queries = []

    for dependency in dependencies:
        queries.append({
            "package": {
                "name": dependency["package"],
                "ecosystem": dependency["ecosystem"]
            },
            "version": dependency["version"]
        })

    payload = {
        "queries": queries
    }

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            OSV_BATCH_URL,
            json=payload
        )

    response.raise_for_status()

    return response.json().get("results", [])
