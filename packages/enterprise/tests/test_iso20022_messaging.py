"""Tests for ISO 20022 Financial Messaging & In-Flight Kenya Payment Risk Evaluation."""
from datetime import datetime, timezone
import pytest

from toroka_enterprise.integrations.iso20022 import (
    ClearingRail,
    InflightRiskEvaluation,
    ISO20022Engine,
    Pacs002PaymentStatusReport,
    Pacs008CreditTransfer,
    PartyIdentification,
    PaymentDecision,
    RiskTier,
)


def test_pacs008_dict_parsing_and_canonical_event_mapping():
    data = {
        "msg_id": "MSG-20261118-001",
        "end_to_end_id": "E2E-PESALINK-9912",
        "tx_id": "TX-883719",
        "amount": 150000.0,
        "currency": "KES",
        "clearing_rail": "PESALINK",
        "debtor": {
            "name": "Alice Wanjiku",
            "account_number": "01123456789",
            "agent_bic": "KCBKKENA",
            "msisdn": "+254711000111",
        },
        "creditor": {
            "name": "Bob Mutua",
            "account_number": "01198765432",
            "agent_bic": "EQBLKENA",
            "msisdn": "+254722000222",
        },
        "remittance_narrative": "Payment for consultancy services",
    }

    transfer = ISO20022Engine.parse_pacs008_dict(data)

    assert transfer.end_to_end_id == "E2E-PESALINK-9912"
    assert transfer.amount == 150000.0
    assert transfer.clearing_rail == ClearingRail.PESALINK
    assert transfer.debtor.name == "Alice Wanjiku"
    assert transfer.creditor.name == "Bob Mutua"

    # Map to Toroka canonical event
    event = transfer.to_canonical_event(installation_id="inst-test-01")
    assert event["event_id"] == "ev:pacs008:E2E-PESALINK-9912"
    assert event["event_type"] == "core_banking_transfer"
    assert event["source_system"] == "ISO20022_PESALINK"
    assert event["payload"]["amount"] == 150000.0
    assert event["payload"]["debtor_account"] == "01123456789"


def test_pacs008_xml_parsing():
    xml_sample = """<?xml version="1.0" encoding="UTF-8"?>
    <Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.008.001.10">
        <FIToFICstmrCdtTrf>
            <GrpHdr>
                <MsgId>MSG-XML-001</MsgId>
                <NbOfTxs>1</NbOfTxs>
            </GrpHdr>
            <CdtTrfTxInf>
                <PmtId>
                    <EndToEndId>E2E-XML-9988</EndToEndId>
                    <TxId>TX-XML-5544</TxId>
                </PmtId>
                <IntrBkSttlmAmt Ccy="KES">450000.00</IntrBkSttlmAmt>
                <ClrSysPrtry>PESALINK</ClrSysPrtry>
                <Dbtr>
                    <Nm>Corporate Debtor Ltd</Nm>
                    <CtctDtls><MobNb>+254700000001</MobNb></CtctDtls>
                </Dbtr>
                <DbtrAcct>
                    <Id><Othr><Id>1122334455</Id></Othr></Id>
                </DbtrAcct>
                <DbtrAgt>
                    <FinInstnId><BICFI>BARBKENA</BICFI></FinInstnId>
                </DbtrAgt>
                <Cdtr>
                    <Nm>Beneficiary Mule Corp</Nm>
                </Cdtr>
                <CdtrAcct>
                    <Id><Othr><Id>9988776655</Id></Othr></Id>
                </CdtrAcct>
                <CdtrAgt>
                    <FinInstnId><BICFI>SCBLKENA</BICFI></FinInstnId>
                </CdtrAgt>
                <RmtInf>
                    <Ustrd>Urgent activation fee for settlement</Ustrd>
                </RmtInf>
            </CdtTrfTxInf>
        </FIToFICstmrCdtTrf>
    </Document>
    """

    transfer = ISO20022Engine.parse_pacs008_xml(xml_sample)

    assert transfer.msg_id == "MSG-XML-001"
    assert transfer.end_to_end_id == "E2E-XML-9988"
    assert transfer.amount == 450000.0
    assert transfer.currency == "KES"
    assert transfer.clearing_rail == ClearingRail.PESALINK
    assert transfer.debtor.name == "Corporate Debtor Ltd"
    assert transfer.creditor.name == "Beneficiary Mule Corp"
    assert "activation fee" in transfer.remittance_narrative


def test_inflight_payment_evaluation_rules_and_latency():
    # 1. Normal clean payment -> ALLOW (<100ms)
    clean_transfer = Pacs008CreditTransfer(
        msg_id="MSG-001",
        end_to_end_id="E2E-CLEAN-01",
        tx_id="TX-01",
        amount=5000.0,
        currency="KES",
        debtor=PartyIdentification(name="David", account_number="01111", agent_bic="KCBKKENA"),
        creditor=PartyIdentification(name="Supermarket", account_number="02222", agent_bic="EQBLKENA"),
        clearing_rail=ClearingRail.PESALINK,
        remittance_narrative="Groceries purchase",
    )
    eval_clean = ISO20022Engine.evaluate_inflight_payment(clean_transfer, account_prior_transfers_count=25)

    assert eval_clean.decision == PaymentDecision.ALLOW
    assert eval_clean.risk_tier == RiskTier.LOW
    assert eval_clean.latency_ms < 100.0  # SLA requirement

    # 2. Known Mule match -> BLOCK
    mule_transfer = Pacs008CreditTransfer(
        msg_id="MSG-002",
        end_to_end_id="E2E-MULE-01",
        tx_id="TX-02",
        amount=250000.0,
        currency="KES",
        debtor=PartyIdentification(name="Victim", account_number="03333", agent_bic="KCBKKENA"),
        creditor=PartyIdentification(name="Mule Account", account_number="MULE_ACC_99", agent_bic="EQBLKENA"),
        clearing_rail=ClearingRail.PESALINK,
        remittance_narrative="Investment returns release",
    )
    eval_mule = ISO20022Engine.evaluate_inflight_payment(
        mule_transfer,
        known_mule_accounts={"MULE_ACC_99"},
    )

    assert eval_mule.decision == PaymentDecision.BLOCK
    assert eval_mule.risk_tier == RiskTier.CRITICAL
    assert any("MULE_ACCOUNT_MATCH" in r for r in eval_mule.triggered_rules)

    # 3. Suspicious Narrative match -> QUARANTINE_HOLD / STEP_UP_AUTH
    scam_transfer = Pacs008CreditTransfer(
        msg_id="MSG-003",
        end_to_end_id="E2E-SCAM-01",
        tx_id="TX-03",
        amount=300000.0,
        currency="KES",
        debtor=PartyIdentification(name="User", account_number="04444", agent_bic="KCBKKENA"),
        creditor=PartyIdentification(name="Unknown", account_number="05555", agent_bic="EQBLKENA"),
        clearing_rail=ClearingRail.PESALINK,
        remittance_narrative="Urgent unlock fee for bitcoin investment",
    )
    eval_scam = ISO20022Engine.evaluate_inflight_payment(scam_transfer, account_prior_transfers_count=0)

    assert eval_scam.decision in (PaymentDecision.QUARANTINE_HOLD, PaymentDecision.BLOCK)
    assert any("SUSPICIOUS_NARRATIVE" in r for r in eval_scam.triggered_rules)


def test_pacs002_reversal_generation():
    transfer = Pacs008CreditTransfer(
        msg_id="MSG-ORIG-01",
        end_to_end_id="E2E-REVERSAL-01",
        tx_id="TX-ORIG-01",
        amount=500000.0,
        currency="KES",
        debtor=PartyIdentification(name="Victim", account_number="111", agent_bic="KCBKKENA"),
        creditor=PartyIdentification(name="Scammer", account_number="222", agent_bic="EQBLKENA"),
        clearing_rail=ClearingRail.PESALINK,
    )
    reversal = ISO20022Engine.generate_pacs002_reversal(
        transfer,
        reason_code="FRAD",
        additional_info="Blocked by Toroka Real-Time Anti-Fraud Engine",
    )

    assert reversal.tx_status == "RJCT"
    assert reversal.reason_code == "FRAD"
    assert reversal.original_end_to_end_id == "E2E-REVERSAL-01"
    assert reversal.original_msg_id == "MSG-ORIG-01"
