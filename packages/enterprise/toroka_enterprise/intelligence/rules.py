from __future__ import annotations

from datetime import datetime
from .events import IntelligenceEvent
from .signals import CorrelationSignal, SignalSeverity


def employee_access_before_sensitive_change(
    events: list[IntelligenceEvent],
) -> list[CorrelationSignal]:
    """Rule A: Customer record access followed shortly by sensitive account profile change."""
    signals: list[CorrelationSignal] = []

    accesses = [
        e for e in events
        if e.event_type in {"customer_record_access", "customer_inquiry", "cif_lookup"}
        and e.actor
    ]

    changes = [
        e for e in events
        if e.event_type in {
            "beneficiary_change",
            "account_profile_change",
            "transaction_limit_change",
            "mandate_change",
        }
    ]

    for access in accesses:
        for change in changes:
            if access.actor is None or change.subject is None:
                continue

            if change.event_time < access.event_time:
                continue

            elapsed = (change.event_time - access.event_time).total_seconds()
            if elapsed > 30 * 60:  # 30-minute window
                continue

            if access.subject != change.subject:
                continue

            signals.append(
                CorrelationSignal(
                    signal_id=f"access-change:{access.event_id}:{change.event_id}",
                    signal_type="access_before_sensitive_change",
                    severity=SignalSeverity.MEDIUM,
                    title="Customer record access preceded sensitive account change",
                    explanation=(
                        f"Employee '{access.actor}' accessed customer profile '{access.subject}' "
                        f"{int(elapsed // 60)}m before a sensitive '{change.event_type}' change occurred."
                    ),
                    event_ids=(access.event_id, change.event_id),
                    confidence=0.82,
                    evidence=(
                        {
                            "event_id": access.event_id,
                            "event_type": access.event_type,
                            "source": access.source_system,
                            "timestamp": access.event_time.isoformat(),
                            "actor": access.actor,
                        },
                        {
                            "event_id": change.event_id,
                            "event_type": change.event_type,
                            "source": change.source_system,
                            "timestamp": change.event_time.isoformat(),
                            "subject": change.subject,
                        },
                    ),
                    alternative_explanations=(
                        "The employee may have been responding to a legitimate customer service request.",
                        "A valid branch mandate update workflow may explain the sequence.",
                    ),
                    missing_evidence=(
                        "customer_service_ticket",
                        "maker_checker_approval",
                    ),
                )
            )

    return signals


def privileged_login_before_unusual_transaction(
    events: list[IntelligenceEvent],
) -> list[CorrelationSignal]:
    """Rule B: Privileged authentication or elevation followed by unusual posting activity."""
    signals: list[CorrelationSignal] = []

    elevations = [
        e for e in events
        if e.event_type in {"privileged_login", "admin_elevation", "super_user_override"}
        and e.actor
    ]

    transactions = [
        e for e in events
        if e.event_type in {
            "high_value_transfer",
            "manual_posting",
            "limit_override_posting",
            "cash_balancing_posting",
        }
    ]

    for elev in elevations:
        for txn in transactions:
            if elev.actor is None:
                continue

            # Must be initiated by same actor or session
            if txn.actor and txn.actor != elev.actor:
                continue

            if txn.event_time < elev.event_time:
                continue

            elapsed = (txn.event_time - elev.event_time).total_seconds()
            if elapsed > 60 * 60:  # 60-minute window
                continue

            signals.append(
                CorrelationSignal(
                    signal_id=f"elevation-txn:{elev.event_id}:{txn.event_id}",
                    signal_type="privileged_login_before_unusual_transaction",
                    severity=SignalSeverity.HIGH,
                    title="Privileged authentication preceded manual or override transaction",
                    explanation=(
                        f"Staff member '{elev.actor}' authenticated with privileged credentials "
                        f"{int(elapsed // 60)}m prior to posting '{txn.event_type}' (ID: {txn.event_id})."
                    ),
                    event_ids=(elev.event_id, txn.event_id),
                    confidence=0.85,
                    evidence=(
                        {
                            "event_id": elev.event_id,
                            "event_type": elev.event_type,
                            "source": elev.source_system,
                            "actor": elev.actor,
                        },
                        {
                            "event_id": txn.event_id,
                            "event_type": txn.event_type,
                            "source": txn.source_system,
                            "amount": txn.attributes.get("amount"),
                        },
                    ),
                    alternative_explanations=(
                        "Scheduled end-of-day branch balancing operations.",
                        "Urgent senior-officer transaction override requested by branch manager.",
                    ),
                    missing_evidence=(
                        "dual_control_authorisation_record",
                        "incident_or_change_ticket",
                    ),
                )
            )

    return signals


def role_change_before_sensitive_activity(
    events: list[IntelligenceEvent],
) -> list[CorrelationSignal]:
    """Rule C: Role or permission modification followed by sensitive operational actions."""
    signals: list[CorrelationSignal] = []

    role_changes = [
        e for e in events
        if e.event_type in {"role_assignment", "permission_grant", "profile_elevation"}
        and (e.subject or e.actor)
    ]

    sensitive_actions = [
        e for e in events
        if e.event_type in {
            "gl_posting",
            "bulk_payout",
            "system_parameter_change",
            "account_freeze_lift",
        }
    ]

    for rc in role_changes:
        affected_staff = rc.subject or rc.actor
        for act in sensitive_actions:
            if act.actor is None or act.actor != affected_staff:
                continue

            if act.event_time < rc.event_time:
                continue

            elapsed = (act.event_time - rc.event_time).total_seconds()
            if elapsed > 24 * 3600:  # 24-hour window
                continue

            signals.append(
                CorrelationSignal(
                    signal_id=f"role-activity:{rc.event_id}:{act.event_id}",
                    signal_type="role_change_before_sensitive_activity",
                    severity=SignalSeverity.MEDIUM,
                    title="Staff permission grant followed by sensitive administrative or financial action",
                    explanation=(
                        f"Staff member '{affected_staff}' received permission grant '{rc.attributes.get('role', rc.event_type)}' "
                        f"and executed sensitive action '{act.event_type}' within {int(elapsed // 3600)} hours."
                    ),
                    event_ids=(rc.event_id, act.event_id),
                    confidence=0.78,
                    evidence=(
                        {
                            "event_id": rc.event_id,
                            "event_type": rc.event_type,
                            "source": rc.source_system,
                            "granted_to": affected_staff,
                        },
                        {
                            "event_id": act.event_id,
                            "event_type": act.event_type,
                            "source": act.source_system,
                            "actor": act.actor,
                        },
                    ),
                    alternative_explanations=(
                        "Planned staff onboarding, promotion, or departmental job rotation.",
                        "Scheduled cross-training under supervisory guidance.",
                    ),
                    missing_evidence=(
                        "hr_promotion_or_transfer_letter",
                        "ciso_privilege_request_form",
                    ),
                )
            )

    return signals


def employee_activity_before_reversal_or_closure(
    events: list[IntelligenceEvent],
) -> list[CorrelationSignal]:
    """Rule D: Employee activity shortly before account closure or transaction reversal."""
    signals: list[CorrelationSignal] = []

    activities = [
        e for e in events
        if e.event_type in {"manual_posting", "customer_record_access", "account_profile_change"}
        and e.actor
    ]

    reversals = [
        e for e in events
        if e.event_type in {"transaction_reversal", "account_closure", "chargeback_processed"}
    ]

    for act in activities:
        for rev in reversals:
            # Check for shared account or customer entity
            shared_entities = set(act.entities).intersection(set(rev.entities))
            if not shared_entities and act.subject != rev.subject:
                continue

            if rev.event_time < act.event_time:
                continue

            elapsed = (rev.event_time - act.event_time).total_seconds()
            if elapsed > 60 * 60:  # 60-minute window
                continue

            signals.append(
                CorrelationSignal(
                    signal_id=f"activity-reversal:{act.event_id}:{rev.event_id}",
                    signal_type="employee_activity_before_reversal_or_closure",
                    severity=SignalSeverity.MEDIUM,
                    title="Employee activity preceded transaction reversal or account closure",
                    explanation=(
                        f"Staff member '{act.actor}' conducted activity '{act.event_type}' "
                        f"{int(elapsed // 60)}m prior to '{rev.event_type}' on shared entity."
                    ),
                    event_ids=(act.event_id, rev.event_id),
                    confidence=0.80,
                    evidence=(
                        {
                            "event_id": act.event_id,
                            "event_type": act.event_type,
                            "actor": act.actor,
                        },
                        {
                            "event_id": rev.event_id,
                            "event_type": rev.event_type,
                            "source": rev.source_system,
                        },
                    ),
                    alternative_explanations=(
                        "Immediate correction of a teller keying error.",
                        "Routine customer-requested cancellation handled by customer service.",
                    ),
                    missing_evidence=(
                        "error_reversal_voucher",
                        "customer_closure_request_form",
                    ),
                )
            )

    return signals


def customer_complaint_correlated_employee_activity(
    events: list[IntelligenceEvent],
) -> list[CorrelationSignal]:
    """Rule E: Customer complaint accompanied or closely followed by unassigned staff lookups."""
    signals: list[CorrelationSignal] = []

    complaints = [
        e for e in events
        if e.event_type in {"customer_complaint", "dispute_lodged", "fraud_inquiry"}
        and e.subject
    ]

    lookups = [
        e for e in events
        if e.event_type in {"customer_record_access", "cif_lookup", "statement_export"}
        and e.actor
    ]

    for comp in complaints:
        for lk in lookups:
            if lk.subject and lk.subject != comp.subject:
                continue

            # Check window within +/- 24 hours of complaint
            diff = abs((lk.event_time - comp.event_time).total_seconds())
            if diff > 24 * 3600:
                continue

            signals.append(
                CorrelationSignal(
                    signal_id=f"complaint-lookup:{comp.event_id}:{lk.event_id}",
                    signal_type="customer_complaint_correlated_employee_activity",
                    severity=SignalSeverity.LOW,
                    title="Customer dispute or complaint correlated with employee profile inquiry",
                    explanation=(
                        f"Customer dispute '{comp.event_id}' is temporally correlated with record inquiry "
                        f"by staff '{lk.actor}' within {int(diff // 3600)}h."
                    ),
                    event_ids=(comp.event_id, lk.event_id),
                    confidence=0.72,
                    evidence=(
                        {
                            "event_id": comp.event_id,
                            "event_type": comp.event_type,
                            "subject": comp.subject,
                        },
                        {
                            "event_id": lk.event_id,
                            "event_type": lk.event_type,
                            "actor": lk.actor,
                        },
                    ),
                    alternative_explanations=(
                        "Assigned customer relationship officer investigating customer complaint.",
                        "Contact center agent actively answering customer inquiry.",
                    ),
                    missing_evidence=(
                        "crm_dispute_case_assignment",
                        "call_recording_id",
                    ),
                )
            )

    return signals


def authentication_anomaly_with_sensitive_action(
    events: list[IntelligenceEvent],
) -> list[CorrelationSignal]:
    """Rule F: Authentication from uncharacteristic device/IP followed by sensitive action."""
    signals: list[CorrelationSignal] = []

    logins = [
        e for e in events
        if e.event_type in {"new_device_login", "abnormal_ip_login", "vpn_concurrent_session"}
        and e.actor
    ]

    actions = [
        e for e in events
        if e.event_type in {
            "credential_reset",
            "password_change",
            "funds_transfer",
            "statement_export",
        }
    ]

    for lg in logins:
        for act in actions:
            if act.actor and act.actor != lg.actor:
                continue

            if act.event_time < lg.event_time:
                continue

            elapsed = (act.event_time - lg.event_time).total_seconds()
            if elapsed > 45 * 60:  # 45-minute window
                continue

            signals.append(
                CorrelationSignal(
                    signal_id=f"auth-anomaly-action:{lg.event_id}:{act.event_id}",
                    signal_type="authentication_anomaly_with_sensitive_action",
                    severity=SignalSeverity.HIGH,
                    title="Uncharacteristic authentication followed by sensitive action",
                    explanation=(
                        f"Actor '{lg.actor}' authenticated via '{lg.event_type}' and executed "
                        f"sensitive action '{act.event_type}' within {int(elapsed // 60)}m."
                    ),
                    event_ids=(lg.event_id, act.event_id),
                    confidence=0.88,
                    evidence=(
                        {
                            "event_id": lg.event_id,
                            "event_type": lg.event_type,
                            "source": lg.source_system,
                            "ip": lg.attributes.get("ip_address"),
                        },
                        {
                            "event_id": act.event_id,
                            "event_type": act.event_type,
                            "source": act.source_system,
                        },
                    ),
                    alternative_explanations=(
                        "Employee telecommuting or traveling using new approved corporate hardware.",
                        "IT department dynamic IP address reassignment.",
                    ),
                    missing_evidence=(
                        "it_service_desk_asset_tag",
                        "mfa_challenge_verification_log",
                    ),
                )
            )

    return signals


def run_all_correlation_rules(
    events: list[IntelligenceEvent],
) -> list[CorrelationSignal]:
    """Execute all active cross-system correlation rules against the event set."""
    signals: list[CorrelationSignal] = []
    signals.extend(employee_access_before_sensitive_change(events))
    signals.extend(privileged_login_before_unusual_transaction(events))
    signals.extend(role_change_before_sensitive_activity(events))
    signals.extend(employee_activity_before_reversal_or_closure(events))
    signals.extend(customer_complaint_correlated_employee_activity(events))
    signals.extend(authentication_anomaly_with_sensitive_action(events))
    return signals
