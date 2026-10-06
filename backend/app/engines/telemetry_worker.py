import asyncio
import random
import logging
import datetime
from typing import Optional
from sqlalchemy import select, update
from app.db.session import AsyncSessionLocal
from app.db.models.models import Atm, AtmStatus, NetworkStatus, SensorType, SensorState
from app.engines.notifier import hub

logger = logging.getLogger("securevault.telemetry")


class FleetTelemetryEngine:
    """
    Real-time ATM Fleet Telemetry & Event Engine.
    Maintains continuous live telemetry streams, heartbeat synchronizations,
    sensor monitoring, and real-time WebSocket event broadcasts.
    """
    def __init__(self):
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._iteration = 0

    def start(self):
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._telemetry_loop())
        logger.info("FleetTelemetryEngine started in background.")

    async def stop(self):
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("FleetTelemetryEngine stopped.")

    async def _telemetry_loop(self):
        # Initial small delay to let server startup settle
        await asyncio.sleep(2)
        while self._running:
            try:
                await self._step_telemetry()
                self._iteration += 1
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in telemetry loop: {e}", exc_info=False)

            # Sleep 4 seconds between telemetry pulses
            try:
                await asyncio.sleep(4)
            except asyncio.CancelledError:
                break

    async def _step_telemetry(self):
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        async with AsyncSessionLocal() as db:
            stmt = select(Atm).order_by(Atm.id)
            res = await db.execute(stmt)
            atms = res.scalars().all()

            if not atms:
                return

            telemetry_snapshot = []
            for atm in atms:
                # Calculate realistic fluctuating metrics
                if atm.status == AtmStatus.LOCKDOWN or atm.under_attack:
                    # High stress telemetry
                    atm.cpu_usage = min(98, max(70, atm.cpu_usage + random.randint(-4, 5)))
                    atm.memory_usage = min(95, max(65, atm.memory_usage + random.randint(-2, 3)))
                    atm.latency_ms = min(220, max(80, atm.latency_ms + random.randint(-10, 15)))
                elif atm.status == AtmStatus.OFFLINE:
                    atm.cpu_usage = 0
                    atm.memory_usage = 0
                    atm.latency_ms = 999
                else:
                    # Healthy fluctuating telemetry
                    delta_cpu = random.choice([-2, -1, 0, 1, 2])
                    atm.cpu_usage = min(42, max(12, atm.cpu_usage + delta_cpu))
                    delta_mem = random.choice([-1, 0, 1])
                    atm.memory_usage = min(56, max(25, atm.memory_usage + delta_mem))
                    delta_lat = random.choice([-3, -1, 0, 1, 2, 4])
                    atm.latency_ms = min(50, max(14, atm.latency_ms + delta_lat))

                # Update heartbeat to current timestamp if not offline
                if atm.status != AtmStatus.OFFLINE:
                    atm.last_heartbeat = now_utc

                telemetry_snapshot.append({
                    "id": atm.id,
                    "atm_code": atm.atm_code,
                    "city": atm.city,
                    "status": atm.status.value,
                    "network_status": atm.network_status.value,
                    "cpu_usage": atm.cpu_usage,
                    "memory_usage": atm.memory_usage,
                    "disk_usage": atm.disk_usage,
                    "latency_ms": atm.latency_ms,
                    "risk_score": atm.risk_score,
                    "under_attack": atm.under_attack,
                    "cash_total": float(atm.cash_total),
                    "firmware_version": atm.firmware_version,
                    "certificate_status": atm.certificate_status,
                    "last_heartbeat": atm.last_heartbeat.isoformat()
                })

            await db.commit()

            # Broadcast live fleet telemetry to all connected WebSocket clients
            await hub.broadcast({
                "type": "ATM_TELEMETRY_UPDATE",
                "timestamp": now_utc.isoformat(),
                "atms": telemetry_snapshot
            })


# Global Engine Instance
telemetry_engine = FleetTelemetryEngine()
