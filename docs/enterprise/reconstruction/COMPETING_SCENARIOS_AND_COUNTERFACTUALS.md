# Competing Scenarios & Counterfactual Analysis

## 1. The Confirmation Bias Problem in Bank Investigations

In conventional fraud triage, an investigator receives an alert labeled *"Suspicious Insider Activity"*. Naturally, the investigator begins searching for evidence that confirms this suspicion, often overlooking evidence that points to:
- A customer-authorized request executed during an emergency.
- Credential compromise by an external adversary.
- A batch processing glitch, network retry, or middleware integration bug.

To eliminate confirmation bias, Toroka adopts the **Analysis of Competing Hypotheses (ACH)** intelligence methodology developed by Richards Heuer for rigorous intelligence analysis.

---

## 2. Standardized Investigation Scenarios

For every reconstructed incident, the engine automatically generates and evaluates four standardized competing scenarios:

```text
                           RECONSTRUCTED INCIDENT
                                     │
         ┌───────────────────────────┼───────────────────────────┐
         ▼                           ▼                           ▼
┌──────────────────┐       ┌──────────────────┐        ┌──────────────────┐
│   Scenario 1:    │       │   Scenario 2:    │        │   Scenario 3:    │
│    Legitimate    │       │     Insider      │        │   Credential     │
│     Service      │       │      Misuse      │        │    Compromise    │
└────────┬─────────┘       └────────┬─────────┘        └────────┬─────────┘
         │                          │                           │
         └──────────────────────────┼───────────────────────────┘
                                    │
                                    ▼
                         ┌────────────────────┐
                         │    Scenario 4:     │
                         │    System Error    │
                         └────────────────────┘
```

### Scenario 1: Legitimate Customer Service (`legitimate_service`)
- **Premise**: The observed actions were authorized by the customer and performed by the bank employee within normal operational duty.
- **Supporting Evidence**:
  - Customer contact records in CRM matching the timeframe.
  - Action performed from employee's assigned branch during normal operating hours.
  - Known device and trusted IP address.
- **Refuting Evidence**:
  - Lack of customer contact record.
  - After-hours execution without supervisor ticket.
  - Sudden change in disbursement account immediately prior to transfer.

### Scenario 2: Insider Misuse (`insider_misuse`)
- **Premise**: The employee intentionally leveraged their legitimate access privileges for unauthorized financial gain or collusion.
- **Supporting Evidence**:
  - Beneficiary account linked to employee's family, personal phone, or known mule network.
  - Action performed during off-hours or following a recent disciplinary/performance event.
  - Prior browsing of multiple high-value dormant customer accounts without operational justification.
- **Refuting Evidence**:
  - Valid CRM service ticket with inbound call recording.
  - Concurrent physical presence at a different branch corroborated by physical access logs.

### Scenario 3: Compromised Credentials (`compromised_credentials`)
- **Premise**: An external threat actor obtained the employee's credentials (via phishing, infostealer malware, or session hijacking) and executed the transactions.
- **Supporting Evidence**:
  - Unrecognized device fingerprint, user-agent string, or external IP address.
  - Concurrent active sessions from impossible geographic locations (velocity violation).
  - SIEM alerts for infostealer malware or anomalous Kerberos ticket requests.
- **Refuting Evidence**:
  - Biometric MFA authentication succeeded on employee's physical hardware token.
  - Workstation physically located on internal teller network with no external gateway access.

### Scenario 4: System Error or Integration Glitch (`system_error`)
- **Premise**: The duplicate postings, missing authorizations, or unusual transaction volumes were caused by a software defect, network retry timeout, or batch processing failure.
- **Supporting Evidence**:
  - Identical retry payloads submitted within milliseconds of each other.
  - Downstream core banking timeout error codes followed by duplicate ledger postings.
  - Known system maintenance or scheduled batch job running concurrently.
- **Refuting Evidence**:
  - Deliberate manual form entry with varying narration strings.
  - Manual creation of an external payee profile prior to fund movement.

---

## 3. Evaluation & Ranking Protocol

Each scenario is evaluated against the complete canonical event log and assigned:
1. `plausibility`: Qualitative classification (`LOW`, `MEDIUM`, `HIGH`).
2. `supporting_evidence`: List of specific event IDs and facts consistent with the scenario.
3. `refuting_evidence`: List of specific event IDs and facts that contradict the scenario.
4. `required_telemetry_to_confirm`: Actions or logs needed to definitively confirm or eliminate the scenario (e.g., *"Retrieve audio recording of customer service call from Avaya call logger"*).

The engine **does not declare a single "winning" scenario**. It presents all four scenarios side-by-side in the Enterprise Workbench, empowering investigators and compliance authorisers to test hypotheses objectively.
