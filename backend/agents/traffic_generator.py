import asyncio
import random
import httpx
import uuid


async def generate_simulated_traffic(base_url: str = "http://localhost:8000", total_requests: int = 15):
    """Generates a mixture of normal and abnormal ATM kiosk queries against the local API."""
    print(f"[*] Starting realistic banking traffic generator against {base_url}...")
    async with httpx.AsyncClient(base_url=base_url, timeout=10.0) as client:
        # Check health
        try:
            health = await client.get("/health")
            print(f"[+] Server health check: {health.json()}")
        except Exception as e:
            print(f"[!] Server unreachable at {base_url}: {e}")
            return

        # Fetch ATM list
        res_atms = await client.get("/api/v1/atm")
        if res_atms.status_code == 200:
            atms = res_atms.json()
            print(f"[+] Discovered {len(atms)} active ATM nodes across network.")
        else:
            print("[!] Could not fetch ATM list.")
            return

        for i in range(total_requests):
            atm = random.choice(atms)
            # Query ATM state
            res = await client.get(f"/api/v1/atm/{atm['id']}")
            print(f"[Req {i+1}/{total_requests}] ATM {atm['atm_code']} ({atm['city']}) status: {res.status_code}")
            await asyncio.sleep(0.5)

    print("[*] Traffic generation completed.")


if __name__ == "__main__":
    asyncio.run(generate_simulated_traffic())
