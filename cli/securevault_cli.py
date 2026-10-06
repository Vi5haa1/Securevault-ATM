import sys
import os
import asyncio
import json
from decimal import Decimal
import typer
from rich.console import Console
from rich.table import Table

# Add backend directory to sys.path so app imports work
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.db.session import AsyncSessionLocal, engine
from app.db.base import Base
from app.db.seed import seed_database
from app.db.models.models import User, UserRole, Incident, AuditLog
from app.core.security import hash_password
from app.audit.verifier import verify_audit_chain
from app.simulation.runner import SimulationRunner

app = typer.Typer(help="SecureVault ATM Administrative & Security CLI")
console = Console()


@app.command()
def seed():
    """Seeds the database with 16 ATMs, 25 customers, staff accounts, and 60-day history."""
    async def _run():
        console.print("[bold blue]Ensuring database schema tables exist...[/bold blue]")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        console.print("[bold green]Executing seed procedure...[/bold green]")
        async with AsyncSessionLocal() as db:
            await seed_database(db)
        console.print("[bold green][OK] Database successfully seeded![/bold green]")

    asyncio.run(_run())


@app.command()
def verify_audit():
    """Verifies the cryptographic SHA-256 hash chain of the audit trail."""
    async def _run():
        console.print("[bold cyan]Verifying cryptographic audit log chain...[/bold cyan]")
        async with AsyncSessionLocal() as db:
            result = await verify_audit_chain(db)

        table = Table(title="Cryptographic Audit Integrity")
        table.add_column("Metric", style="bold")
        table.add_column("Value")

        table.add_row("Total Audit Logs", str(result["total_logs"]))
        table.add_row("Verified Logs", str(result["verified_logs"]))
        
        status_color = "green" if result["status"] == "VALID" else "bold red"
        table.add_row("Chain Integrity", f"[{status_color}]{result['status']}[/{status_color}]")
        table.add_row("Details", result["details"])

        if result["tampered"]:
            table.add_row("Broken Sequence #", str(result["broken_sequence_no"]))
            table.add_row("Broken Log ID", str(result["broken_log_id"]))

        console.print(table)

    asyncio.run(_run())


@app.command()
def create_staff(
    username: str = typer.Option(..., prompt=True),
    email: str = typer.Option(..., prompt=True),
    role: str = typer.Option("SECURITY_ANALYST", help="ATM_OPERATOR | SECURITY_ANALYST | BANK_ADMIN | SUPER_ADMIN"),
    password: str = typer.Option(..., prompt=True, hide_input=True)
):
    """Creates a new internal staff user."""
    async def _run():
        async with AsyncSessionLocal() as db:
            u = User(
                username=username,
                email=email,
                phone="+919800000000",
                password_hash=hash_password(password),
                role=UserRole(role.upper()),
                enabled=True,
                mfa_enabled=False
            )
            db.add(u)
            await db.commit()
            console.print(f"[bold green][OK] Staff user '{username}' ({role}) created successfully![/bold green]")

    asyncio.run(_run())


@app.command()
def simulate(
    simulation_type: str = typer.Option("BRUTE_FORCE", help="BRUTE_FORCE | SUSPICIOUS_TXN | ATM_TAMPER | API_ABUSE | UNAUTHORIZED_ACCESS | SESSION_ABUSE"),
    atm_id: int = typer.Option(1, help="Target ATM ID"),
):
    """Executes an internal defensive attack simulation."""
    async def _run():
        console.print(f"[bold yellow]Executing {simulation_type} simulation against ATM #{atm_id}...[/bold yellow]")
        async with AsyncSessionLocal() as db:
            res = await SimulationRunner.run_simulation(
                db=db,
                simulation_type=simulation_type,
                atm_id=atm_id
            )
            await db.commit()

        console.print(f"[bold green][OK] Threat Detected:[/bold green] {res['threat_detected']}")
        console.print(f"[bold cyan]Rule Triggered:[/bold cyan] {res['detection_rule']}")
        if res.get('incident_code'):
            console.print(f"[bold red]Incident Created:[/bold red] {res['incident_code']}")
        for step in res['steps']:
            console.print(f"  * {step['step']}: {step['detail']}")

    asyncio.run(_run())


@app.command()
def export_incidents(output_file: str = "logs/incident_report.json"):
    """Exports all incidents to a formatted JSON report."""
    async def _run():
        async with AsyncSessionLocal() as db:
            from sqlalchemy import select
            stmt = select(Incident)
            res = await db.execute(stmt)
            incidents = res.scalars().all()

            data = [{
                "code": i.incident_code,
                "severity": i.severity.value,
                "threat_type": i.threat_type,
                "status": i.status.value,
                "summary": i.summary,
                "created_at": i.created_at.isoformat(),
                "is_simulated": i.is_simulated
            } for i in incidents]

            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)

            console.print(f"[bold green][OK] Exported {len(data)} incidents to '{output_file}'[/bold green]")

    asyncio.run(_run())


if __name__ == "__main__":
    app()
