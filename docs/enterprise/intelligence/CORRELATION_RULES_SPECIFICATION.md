# Toroka Enterprise — Cross-System Correlation Rules Specification

## 1. Overview & Rule Philosophy

Toroka's cross-system correlation rules are **deterministic, explainable, and non-accusatory**. Each rule requires:
1. Defined temporal window.
2. Cross-system event trigger sequence.
3. Plausible alternative explanations (benign operational context).
4. Explicit missing evidence checklist.

---

## 2. Rule Catalog

### Rule A: Employee Access Before Sensitive Change (`employee_access_before_sensitive_change`)
- **Trigger**: Staff queries customer CIF/account (`customer_record_access`, `customer_inquiry`, `cif_lookup`) and, within 30 minutes, a sensitive account modification (`beneficiary_change`, `account_profile_change`, `transaction_limit_change`, `mandate_change`) is posted on the same customer.
- **Severity**: `MEDIUM`
- **Pattern Confidence**: `0.82`
- **Alternative Explanations**:
  - Employee was responding to an authorized customer request physically present at the branch.
  - A valid customer service mandate update was in progress.
- **Missing Evidence**: `customer_service_ticket`, `maker_checker_approval`.

---

### Rule B: Privileged Login Before Unusual Transaction (`privileged_login_before_unusual_transaction`)
- **Trigger**: Staff logs in with elevated/admin privileges (`privileged_login`, `admin_elevation`, `super_user_override`) and, within 60 minutes, posts a manual or high-value override transaction (`high_value_transfer`, `manual_posting`, `limit_override_posting`, `cash_balancing_posting`).
- **Severity**: `HIGH`
- **Pattern Confidence**: `0.85`
- **Alternative Explanations**:
  - Scheduled end-of-day branch balancing operations.
  - Urgent senior-officer transaction override requested by branch manager.
- **Missing Evidence**: `dual_control_authorisation_record`, `incident_or_change_ticket`.

---

### Rule C: Role Change Before Sensitive Activity (`role_change_before_sensitive_activity`)
- **Trigger**: Staff receives an IAM role or privilege elevation (`role_assignment`, `permission_grant`, `profile_elevation`) and, within 24 hours, executes sensitive administrative or GL actions (`gl_posting`, `bulk_payout`, `system_parameter_change`, `account_freeze_lift`).
- **Severity**: `MEDIUM`
- **Pattern Confidence**: `0.78`
- **Alternative Explanations**:
  - Planned staff promotion, onboarding, or departmental job rotation.
  - Scheduled cross-training under supervisory guidance.
- **Missing Evidence**: `hr_promotion_or_transfer_letter`, `ciso_privilege_request_form`.

---

### Rule D: Employee Activity Before Reversal or Closure (`employee_activity_before_reversal_or_closure`)
- **Trigger**: Staff queries, posts, or alters an account profile and, within 60 minutes, a transaction reversal or account closure occurs on that entity.
- **Severity**: `MEDIUM`
- **Pattern Confidence**: `0.80`
- **Alternative Explanations**:
  - Immediate rectification of a teller keying error.
  - Routine customer-requested cancellation handled at branch counter.
- **Missing Evidence**: `error_reversal_voucher`, `customer_closure_request_form`.

---

### Rule E: Customer Complaint Correlated Staff Inquiries (`customer_complaint_correlated_employee_activity`)
- **Trigger**: Customer lodges a formal complaint or dispute (`customer_complaint`, `dispute_lodged`, `fraud_inquiry`) and, within +/- 24 hours, staff queries or exports statements for that customer without an assigned CRM ticket.
- **Severity**: `LOW`
- **Pattern Confidence**: `0.72`
- **Alternative Explanations**:
  - Assigned customer relationship manager reviewing customer profile to resolve dispute.
  - Contact center agent answering follow-up customer phone inquiry.
- **Missing Evidence**: `crm_dispute_case_assignment`, `call_recording_id`.

---

### Rule F: Authentication Anomaly With Sensitive Action (`authentication_anomaly_with_sensitive_action`)
- **Trigger**: Login occurs from an uncharacteristic IP address or new device (`new_device_login`, `abnormal_ip_login`, `vpn_concurrent_session`) and, within 45 minutes, a sensitive action is executed (`credential_reset`, `password_change`, `funds_transfer`, `statement_export`).
- **Severity**: `HIGH`
- **Pattern Confidence**: `0.88`
- **Alternative Explanations**:
  - Employee telecommuting or traveling using approved corporate hardware.
  - IT department dynamic IP address pool reassignment.
- **Missing Evidence**: `it_service_desk_asset_tag`, `mfa_challenge_verification_log`.
