import pytest
import datetime
from app.engines.event_pipeline import EventPipeline, RawEvent
from app.db.models.models import SeverityLevel, Incident, IncidentStatus, SecurityEvent
from sqlalchemy import select

@pytest.mark.asyncio
async def test_pipeline_failed_pin_correlation(db_session):
    """
    Acceptance Criteria 2:
    Verify that 5 failed PIN attempts within 5 minutes correlate into ONE incident
    with a complete pipeline trace.
    """
    correlation_key = "user-test-card-9999"

    # Emit 5 sequential failed pin events
    results = []
    for i in range(5):
        raw = RawEvent(
            event_type="FAILED_PIN",
            source="ATM_PINPAD",
            severity_hint=SeverityLevel.MEDIUM,
            atm_id=1,
            user_id=1,
            ip_address="192.168.1.100",
            correlation_key=correlation_key,
            raw_payload={"attempt": i + 1, "card_suffix": "9999", "failed_pin": True},
            is_simulated=True
        )
        res = await EventPipeline.process_event(db_session, raw)
        results.append(res)

    # Verify 5 events were normalized and recorded
    stmt = select(SecurityEvent).where(SecurityEvent.correlation_key == correlation_key)
    res_events = await db_session.execute(stmt)
    events = res_events.scalars().all()
    assert len(events) == 5

    # Verify all 5 events carry a pipeline trace
    for ev in events:
        trace = ev.details.get("pipeline_trace", [])
        assert len(trace) >= 4
        stage_names = [t["stage"] for t in trace]
        assert "COLLECT" in stage_names
        assert "NORMALIZE" in stage_names
        assert "CORRELATE" in stage_names

    # Check that by the 5th event, the brute force detection rule fired
    last_res = results[-1]
    assert last_res["incident_code"] is not None
    assert last_res["fired_rule_id"] is not None
    assert len(last_res["actions_executed"]) >= 1
    
    # Verify exactly ONE incident was created for this brute-force attack
    inc_stmt = select(Incident).where(Incident.incident_code == last_res["incident_code"])
    inc_res = await db_session.execute(inc_stmt)
    incidents = inc_res.scalars().all()
    assert len(incidents) == 1
    assert incidents[0].status == IncidentStatus.OPEN
    # Check that subsequent events reference the same open incident rather than spawning multiples
    incident_ids = {e.incident_id for e in events if e.incident_id is not None}
    assert len(incident_ids) == 1
