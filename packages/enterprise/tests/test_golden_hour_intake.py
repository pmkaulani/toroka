from datetime import datetime, timedelta, timezone
from decimal import Decimal

from toroka_enterprise.integrations.golden_hour_intake import (
    GoldenHourInterceptorEngine,
    GoldenHourReportStatus,
    SwitchFreezeStatus,
    TargetRecipientDirective,
)


def test_golden_hour_within_120_minutes():
    """Helpline 1930 / CFCFRMS intake within 2 hours triggers active Golden Hour."""
    now = datetime.now(timezone.utc)
    incident_time = now - timedelta(minutes=45)  # 45 minutes ago

    targets = [
        TargetRecipientDirective(
            recipient_account="ACC-MULE-INDIA-01",
            recipient_institution_bic="SBIN0001",
            amount_flagged=Decimal("250000.00"),
        )
    ]

    report = GoldenHourInterceptorEngine.ingest_emergency_report(
        victim_account_id="ACC-VICTIM-99",
        victim_phone="+919876543210",
        scam_category="DIGITAL_ARREST_POLICE_IMPERSONATION",
        incident_time=incident_time,
        reported_time=now,
        total_amount_lost=Decimal("250000.00"),
        transaction_references=["UPI-REF-001", "UPI-REF-002"],
        target_recipients=targets,
    )

    assert report.is_golden_hour is True
    assert report.status == GoldenHourReportStatus.GOLDEN_HOUR_ACTIVE
    assert report.elapsed_minutes == 45.0
    assert report.switch_freeze_broadcast_id is not None
    assert report.switch_status == SwitchFreezeStatus.BROADCAST_DISPATCHED


def test_golden_hour_exceeded_standard_window():
    """Helpline 1930 / CFCFRMS report at 5 hours post-incident is outside Golden Hour."""
    now = datetime.now(timezone.utc)
    incident_time = now - timedelta(hours=5)

    report = GoldenHourInterceptorEngine.ingest_emergency_report(
        victim_account_id="ACC-VICTIM-99",
        victim_phone="+919876543210",
        scam_category="INVESTMENT_APP_PIG_BUTCHERING",
        incident_time=incident_time,
        reported_time=now,
        total_amount_lost=Decimal("500000.00"),
        transaction_references=["UPI-REF-003"],
        target_recipients=[],
    )

    assert report.is_golden_hour is False
    assert report.status == GoldenHourReportStatus.STANDARD_WINDOW_ACTIVE
