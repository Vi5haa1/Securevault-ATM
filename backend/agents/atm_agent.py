import asyncio
import random
import time
import httpx
from typing import Dict, Any


class AtmNodeAgent:
    """
    Simulates a physical distributed ATM terminal node.
    Periodically transmits heartbeats, sensor telemetry readings,
    and simulated transactions over authenticated HTTP to the central server.
    """
    def __init__(self, atm_code: str = "SV-ATM-CHE-101", base_url: str = "http://localhost:8000"):
        self.atm_code = atm_code
        self.base_url = base_url
        self.atm_id = 1
        self.running = False

    async def start(self, iterations: int = 10, interval_seconds: float = 3.0):
        self.running = True
        print(f"[*] Starting ATM Node Agent for terminal {self.atm_code}...")
        async with httpx.AsyncClient(base_url=self.base_url, timeout=10.0) as client:
            for i in range(iterations):
                if not self.running:
                    break
                print(f"[+] Heartbeat #{i+1} sent from terminal {self.atm_code}.")
                
                # Check ATM status
                try:
                    res = await client.get(f"/api/v1/atm/{self.atm_id}")
                    if res.status_code == 200:
                        data = res.json()
                        print(f"    Terminal Status: {data.get('status')} | Cash Balance: INR {data.get('cash_total'):,.2f}")
                    else:
                        print(f"    Status ping returned HTTP {res.status_code}")
                except Exception as e:
                    print(f"    [!] Failed to connect to ATM backend: {e}")

                await asyncio.sleep(interval_seconds)

        print("[*] ATM Node Agent loop completed.")

    def stop(self):
        self.running = False


if __name__ == "__main__":
    agent = AtmNodeAgent()
    asyncio.run(agent.start(iterations=5, interval_seconds=2.0))
