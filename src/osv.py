import httpx

OSV_QUERY_URL = "https://api.osv.dev/v1/query"


async def query_package(
    package: str,
    ecosystem: str,
    version: str
):
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
