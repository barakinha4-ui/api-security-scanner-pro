import httpx
import asyncio
import sys

async def check_status(job_id: str):
    async with httpx.AsyncClient() as client:
        print(f"Checking status for job: {job_id}")
        for _ in range(20):
            resp = await client.get(
                f"http://localhost/api/status/{job_id}",
                headers={"Authorization": "Bearer super-secret-local-key"}
            )
            data = resp.json()
            print(f"Status: {data.get('status')} | Celery: {data.get('celery_state')}")
            if data.get('status') in ['completed', 'failed', 'SUCCESS', 'FAILURE']:
                if 'result' in data:
                    print(f"Result: {data['result']}")
                if 'error' in data:
                    print(f"Error: {data['error']}")
                break
            await asyncio.sleep(5)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python check_status.py <job_id>")
    else:
        asyncio.run(check_status(sys.argv[1]))
