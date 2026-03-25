import httpx
import asyncio

async def main():
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            "http://localhost/api/jobs",
            headers={"Authorization": "Bearer super-secret-local-key"}
        )
        print(f"Status: {resp.status_code}")
        print(f"Body: {resp.text}")

if __name__ == "__main__":
    asyncio.run(main())
