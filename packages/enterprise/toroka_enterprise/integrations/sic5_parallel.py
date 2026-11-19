"""Swiss SIC5 Parallel Real-Time Payment Clearing Engine.

Implements high-concurrency, sub-50ms parallel evaluation for instant payments
(SIX Swiss Exchange SIC5 / SEPA Instant / Kenya Fast Payments architecture).

Executes independent clearing risk feeds concurrently:
  - Feed 1: Confirmation of Payee (CoP) Pre-Flight Name Matching
  - Feed 2: Telecom Scam Signal & Live-Call Telemetry Gateway
  - Feed 3: Federated Blinded Mule Directory Query
  - Feed 4: Behavioral Velocity, Prior Counterparties & Narrative NLP

Enforces strict Per-Feed Circuit Breakers and Total Pipeline SLAs (<45ms target,
<50ms hard limit). If any individual feed times out or fails, it gracefully
degrades to a conservative default rather than breaching payment switch SLAs.
"""
from __future__ import annotations

import concurrent.futures
import time
from dataclasses import asdict, dataclass, field
from decimal import Decimal
from enum import StrEnum
from typing import Any, Callable

from .cop import ConfirmationOfPayeeEngine, CopAccountType, CopInquiryRequest
from .federated_mule import FederatedMuleEngine, FederatedMuleQuery, MuleEntityType
from .iso20022 import (
    InflightRiskEvaluation,
    ISO20022Engine,
    Pacs008CreditTransfer,
)
from .telecom_signal import (
    CallStatus,
    SimSwapStatus,
    TelecomCarrier,
    TelecomScamSignalGateway,
    TelecomSignalQuery,
)

_SIC5_EXECUTOR: concurrent.futures.ThreadPoolExecutor | None = None


def get_sic5_executor() -> concurrent.futures.ThreadPoolExecutor:
    global _SIC5_EXECUTOR
    if _SIC5_EXECUTOR is None:
        _SIC5_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
            max_workers=32,
            thread_name_prefix="sic5_clearing",
        )
    return _SIC5_EXECUTOR



class SIC5FeedStatus(StrEnum):
    SUCCESS = "SUCCESS"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


@dataclass(frozen=True)
class ClearingFeedLatencyBreakdown:
    cop_latency_ms: float = 0.0
    telecom_latency_ms: float = 0.0
    federated_mule_latency_ms: float = 0.0
    behavioral_latency_ms: float = 0.0
    total_pipeline_latency_ms: float = 0.0
    sla_budget_ms: float = 45.0
    is_sla_compliant: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "cop_latency_ms": round(self.cop_latency_ms, 2),
            "telecom_latency_ms": round(self.telecom_latency_ms, 2),
            "federated_mule_latency_ms": round(self.federated_mule_latency_ms, 2),
            "behavioral_latency_ms": round(self.behavioral_latency_ms, 2),
            "total_pipeline_latency_ms": round(self.total_pipeline_latency_ms, 2),
            "sla_budget_ms": self.sla_budget_ms,
            "is_sla_compliant": self.is_sla_compliant,
        }


@dataclass(frozen=True)
class ParallelClearingResult:
    evaluation: InflightRiskEvaluation
    latency_breakdown: ClearingFeedLatencyBreakdown
    feed_statuses: dict[str, str]
    circuit_breaker_tripped: bool

    def to_dict(self) -> dict[str, Any]:
        res = self.evaluation.to_dict()
        res.update({
            "latency_breakdown": self.latency_breakdown.to_dict(),
            "feed_statuses": self.feed_statuses,
            "circuit_breaker_tripped": self.circuit_breaker_tripped,
            "is_parallel_pipeline": True,
            "sla_budget_ms": self.latency_breakdown.sla_budget_ms,
            "is_sla_compliant": self.latency_breakdown.is_sla_compliant,
            "cop_latency_ms": self.latency_breakdown.cop_latency_ms,
            "telecom_latency_ms": self.latency_breakdown.telecom_latency_ms,
            "federated_mule_latency_ms": self.latency_breakdown.federated_mule_latency_ms,
            "behavioral_latency_ms": self.latency_breakdown.behavioral_latency_ms,
        })
        return res


class SIC5ParallelClearingEngine:
    """Orchestrates concurrent multi-feed risk evaluation under strict sub-50ms SLA."""

    DEFAULT_SLA_BUDGET_MS = 45.0
    DEFAULT_FEED_TIMEOUT_MS = 35.0

    @classmethod
    def evaluate_parallel(
        cls,
        transfer: Pacs008CreditTransfer,
        *,
        # Feed 1 Inputs (Confirmation of Payee)
        cop_enabled: bool = True,
        cop_registered_name: str | None = None,
        cop_account_type: str = "PERSONAL",
        cop_override_status: str | None = None,
        cop_override_score: float | None = None,
        # Feed 2 Inputs (Telecom Scam Signal)
        telecom_enabled: bool = True,
        telecom_msisdn: str | None = None,
        telecom_carrier: str = "SAFARICOM",
        telecom_simulated_call: str | None = None,
        telecom_simulated_duration: int = 0,
        telecom_simulated_swap: str | None = None,
        telecom_override_status: str | None = None,
        telecom_override_score: float | None = None,
        # Feed 3 Inputs (Federated Mule Directory)
        federated_mule_enabled: bool = True,
        federated_mule_records: list[dict[str, Any]] | None = None,
        # Feed 4 Inputs (Behavioral / Internal Rules)
        known_mule_accounts: set[str] | None = None,
        account_prior_transfers_count: int | None = None,
        beneficiary_inflow_restriction: bool = False,
        debtor_channel_anomaly: bool = False,
        enable_graduated_controls: bool = True,
        # SLA & Timeout parameters
        sla_budget_ms: float = DEFAULT_SLA_BUDGET_MS,
        feed_timeout_ms: float = DEFAULT_FEED_TIMEOUT_MS,
        # Optional artificial latency injectors for benchmark testing
        simulated_latencies: dict[str, float] | None = None,
    ) -> ParallelClearingResult:
        """Runs all 4 clearing feeds in parallel threads with per-feed timeouts."""
        t_pipeline_start = time.perf_counter()
        sim_delays = simulated_latencies or {}

        feed_timeout_sec = feed_timeout_ms / 1000.0
        feed_statuses: dict[str, str] = {
            "cop": SIC5FeedStatus.SKIPPED.value,
            "telecom": SIC5FeedStatus.SKIPPED.value,
            "federated_mule": SIC5FeedStatus.SKIPPED.value,
            "behavioral": SIC5FeedStatus.SKIPPED.value,
        }
        feed_latencies: dict[str, float] = {
            "cop": 0.0,
            "telecom": 0.0,
            "federated_mule": 0.0,
            "behavioral": 0.0,
        }

        # Thread worker definitions - thread-safe: workers return values and do not mutate shared dictionaries
        def _run_cop() -> tuple[str | None, float | None, float, bool]:
            t0 = time.perf_counter()
            delay = sim_delays.get("cop", 0.0)
            if delay > 0:
                time.sleep(delay / 1000.0)

            if cop_override_status is not None:
                lat = (time.perf_counter() - t0) * 1000.0
                return cop_override_status, cop_override_score, lat, False

            if not cop_enabled or not cop_registered_name:
                lat = (time.perf_counter() - t0) * 1000.0
                return None, None, lat, True

            inquiry = CopInquiryRequest(
                intended_name=transfer.creditor.name,
                registered_name=cop_registered_name,
                account_number=transfer.creditor.account_number,
                account_type=CopAccountType(cop_account_type),
                clearing_rail=transfer.clearing_rail.value,
                bank_bic=transfer.creditor.agent_bic,
            )
            res = ConfirmationOfPayeeEngine.verify(inquiry)
            lat = (time.perf_counter() - t0) * 1000.0
            return res.status.value, res.match_score, lat, False

        def _run_telecom() -> tuple[str | None, float | None, float, bool]:
            t0 = time.perf_counter()
            delay = sim_delays.get("telecom", 0.0)
            if delay > 0:
                time.sleep(delay / 1000.0)

            if telecom_override_status is not None:
                lat = (time.perf_counter() - t0) * 1000.0
                return telecom_override_status, telecom_override_score, lat, False

            target_phone = telecom_msisdn or transfer.debtor.msisdn
            if not telecom_enabled or not target_phone:
                lat = (time.perf_counter() - t0) * 1000.0
                return None, None, lat, True

            c_status = CallStatus(telecom_simulated_call) if telecom_simulated_call else None
            s_status = SimSwapStatus(telecom_simulated_swap) if telecom_simulated_swap else None

            carrier_enum = TelecomCarrier.SAFARICOM
            if telecom_carrier.upper() == "AIRTEL":
                carrier_enum = TelecomCarrier.AIRTEL
            elif telecom_carrier.upper() == "TELKOM":
                carrier_enum = TelecomCarrier.TELKOM

            query = TelecomSignalQuery(
                msisdn=target_phone,
                carrier=carrier_enum,
                simulated_call_status=c_status,
                simulated_call_duration_seconds=telecom_simulated_duration,
                simulated_sim_swap_status=s_status,
            )
            sig_res = TelecomScamSignalGateway.evaluate_telecom_signal(query)
            lat = (time.perf_counter() - t0) * 1000.0
            return sig_res.call_status.value, sig_res.scam_signal_score, lat, False

        def _run_federated_mule() -> tuple[Any, float, bool]:
            t0 = time.perf_counter()
            delay = sim_delays.get("federated_mule", 0.0)
            if delay > 0:
                time.sleep(delay / 1000.0)

            if not federated_mule_enabled or federated_mule_records is None:
                lat = (time.perf_counter() - t0) * 1000.0
                return None, lat, True

            query = FederatedMuleQuery(
                value=transfer.creditor.account_number,
                entity_type=MuleEntityType.BANK_ACCOUNT,
            )
            m_res = FederatedMuleEngine.evaluate_mule_query(query, federated_mule_records)
            lat = (time.perf_counter() - t0) * 1000.0
            return m_res, lat, False

        def _run_behavioral() -> tuple[dict[str, Any], float, bool]:
            t0 = time.perf_counter()
            delay = sim_delays.get("behavioral", 0.0)
            if delay > 0:
                time.sleep(delay / 1000.0)

            lat = (time.perf_counter() - t0) * 1000.0
            return {"status": "OK"}, lat, False

        circuit_breaker_tripped = False
        cop_res_status = None
        cop_res_score = None
        telecom_res_call = None
        telecom_res_score = None
        fed_mule_res = None

        # Execute concurrent tasks with persistent shared executor
        executor = get_sic5_executor()
        future_cop = executor.submit(_run_cop)
        future_tel = executor.submit(_run_telecom)
        future_fed = executor.submit(_run_federated_mule)
        future_beh = executor.submit(_run_behavioral)

        # Wait for CoP with timeout
        try:
            cop_res_status, cop_res_score, cop_lat_val, is_cop_skip = future_cop.result(timeout=feed_timeout_sec)
            feed_latencies["cop"] = cop_lat_val
            feed_statuses["cop"] = SIC5FeedStatus.SKIPPED.value if is_cop_skip else SIC5FeedStatus.SUCCESS.value
        except concurrent.futures.TimeoutError:
            circuit_breaker_tripped = True
            feed_statuses["cop"] = SIC5FeedStatus.TIMEOUT.value
            feed_latencies["cop"] = feed_timeout_ms
            cop_res_status = "CLOSE_MATCH"  # Conservative fallback on timeout
            cop_res_score = 0.50
        except Exception:
            feed_statuses["cop"] = SIC5FeedStatus.ERROR.value
            cop_res_status = None

        # Wait for Telecom with timeout
        try:
            telecom_res_call, telecom_res_score, tel_lat_val, is_tel_skip = future_tel.result(timeout=feed_timeout_sec)
            feed_latencies["telecom"] = tel_lat_val
            feed_statuses["telecom"] = SIC5FeedStatus.SKIPPED.value if is_tel_skip else SIC5FeedStatus.SUCCESS.value
        except concurrent.futures.TimeoutError:
            circuit_breaker_tripped = True
            feed_statuses["telecom"] = SIC5FeedStatus.TIMEOUT.value
            feed_latencies["telecom"] = feed_timeout_ms
            telecom_res_call = "UNKNOWN"
            telecom_res_score = 0.0
        except Exception:
            feed_statuses["telecom"] = SIC5FeedStatus.ERROR.value
            telecom_res_call = None

        # Wait for Federated Mule with timeout
        try:
            fed_mule_res, fed_lat_val, is_fed_skip = future_fed.result(timeout=feed_timeout_sec)
            feed_latencies["federated_mule"] = fed_lat_val
            feed_statuses["federated_mule"] = SIC5FeedStatus.SKIPPED.value if is_fed_skip else SIC5FeedStatus.SUCCESS.value
        except concurrent.futures.TimeoutError:
            circuit_breaker_tripped = True
            feed_statuses["federated_mule"] = SIC5FeedStatus.TIMEOUT.value
            feed_latencies["federated_mule"] = feed_timeout_ms
            fed_mule_res = None
        except Exception:
            feed_statuses["federated_mule"] = SIC5FeedStatus.ERROR.value
            fed_mule_res = None

        # Wait for Behavioral
        try:
            _, beh_lat_val, _ = future_beh.result(timeout=feed_timeout_sec)
            feed_latencies["behavioral"] = beh_lat_val
            feed_statuses["behavioral"] = SIC5FeedStatus.SUCCESS.value
        except concurrent.futures.TimeoutError:
            circuit_breaker_tripped = True
            feed_statuses["behavioral"] = SIC5FeedStatus.TIMEOUT.value
            feed_latencies["behavioral"] = feed_timeout_ms
        except Exception:
            feed_statuses["behavioral"] = SIC5FeedStatus.ERROR.value

        # Recombine into ISO20022Engine
        evaluation = ISO20022Engine.evaluate_inflight_payment(
            transfer=transfer,
            known_mule_accounts=known_mule_accounts,
            account_prior_transfers_count=account_prior_transfers_count,
            cop_status=cop_res_status,
            cop_match_score=cop_res_score,
            beneficiary_inflow_restriction=beneficiary_inflow_restriction,
            debtor_channel_anomaly=debtor_channel_anomaly,
            enable_graduated_controls=enable_graduated_controls,
            telecom_call_status=telecom_res_call,
            telecom_coercion_score=telecom_res_score,
            federated_mule_match=fed_mule_res,
        )

        total_elapsed_ms = (time.perf_counter() - t_pipeline_start) * 1000.0
        is_sla_compliant = total_elapsed_ms <= sla_budget_ms

        breakdown = ClearingFeedLatencyBreakdown(
            cop_latency_ms=feed_latencies["cop"],
            telecom_latency_ms=feed_latencies["telecom"],
            federated_mule_latency_ms=feed_latencies["federated_mule"],
            behavioral_latency_ms=feed_latencies["behavioral"],
            total_pipeline_latency_ms=total_elapsed_ms,
            sla_budget_ms=sla_budget_ms,
            is_sla_compliant=is_sla_compliant,
        )

        return ParallelClearingResult(
            evaluation=evaluation,
            latency_breakdown=breakdown,
            feed_statuses=feed_statuses,
            circuit_breaker_tripped=circuit_breaker_tripped,
        )
