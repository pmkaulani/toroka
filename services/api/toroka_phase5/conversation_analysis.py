from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import re

from .models import EvidenceSignal, SOURCE_GROUPS
from .privacy import safe_excerpt

_PATTERNS: tuple[tuple[str, tuple[str, ...], str, str, float], ...] = (
    ("urgency_pressure", (r"pay\s+(?:now|immediately|today)\s+or", r"last\s+chance", r"within\s+\d+\s+minutes", r"haraka\s+kulipa", r"lipa\s+sasa\s+la sivyo"), "medium", "The conversation contains pressure to act quickly or risk losing an offer.", 0.68),
    ("payment_destination_change", (r"send\s+(?:the\s+money|payment)\s+to\s+(?:this|another|new)\s+(?:number|till|paybill)", r"use\s+(?:(?:my|this|the)\s+)?(?:new\s+)?number\s+instead", r"badili\s+nambari", r"tuma\s+kwa\s+nambari\s+nyingine"), "high", "The sender appears to redirect payment to a different destination.", 0.78),
    ("additional_fee_after_payment", (r"another\s+(?:fee|payment|deposit)\s+(?:is\s+)?required", r"pay\s+the\s+remaining\s+fee", r"ongeza\s+ada", r"lipa\s+ada\s+nyingine"), "high", "A further payment is requested after an earlier payment or fee is discussed.", 0.76),
    ("move_off_platform", (r"continue\s+on\s+whatsapp\s+only", r"message\s+me\s+privately", r"do\s+not\s+use\s+the\s+platform", r"tuma\s+whatsapp\s+peke yake"), "low", "The conversation encourages moving away from the original platform.", 0.58),
    ("credential_request", (r"send\s+(?:me\s+)?your\s+(?:m[- ]?pesa\s+)?pin", r"share\s+the\s+otp", r"tell\s+me\s+the\s+one[- ]time\s+password", r"nipe\s+(?:mpesa\s+)?pin", r"nitumie\s+otp"), "critical", "The sender appears to request a credential or one-time code.", 0.94),
)


@dataclass(frozen=True, slots=True)
class ConversationMessage:
    role: str
    text: str
    timestamp: str | None = None

    def __post_init__(self):
        if self.timestamp:
            from datetime import datetime
            try:
                dt = datetime.fromisoformat(self.timestamp.replace("Z", "+00:00"))
                from datetime import timezone
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                object.__setattr__(self, "timestamp", dt.astimezone(timezone.utc).isoformat())
            except (ValueError, AttributeError) as exc:
                raise ValueError("timestamp must be ISO-8601") from exc
        if self.role not in {"seller", "buyer", "unknown", "platform", "other"}:
            raise ValueError("role must be a predefined conversation role")
        if not isinstance(self.text, str) or len(self.text) > 10_000:
            raise ValueError("message text must be at most 10,000 characters")


def analyze_conversation(
    messages: list[ConversationMessage], *, evidence_ref: str,
    source_group: str = "user_chat",
) -> dict[str, Any]:
    if not messages or len(messages) > 500:
        raise ValueError("messages must contain 1-500 entries")
    if source_group not in SOURCE_GROUPS:
        raise ValueError("invalid source_group")

    signals: list[EvidenceSignal] = []
    observed_categories: set[str] = set()
    seller_texts = [m.text for m in messages if m.role == "seller"]
    for category, alternatives, severity, summary, confidence in _PATTERNS:
        matched_seller = None
        matched_unknown = None
        # Attribute a pattern to a seller only when the trusted importer assigned
        # the seller role. Unknown-role messages remain context-only.
        for pattern in alternatives:
            for msg in messages:
                if msg.role == "seller" and re.search(pattern, msg.text, re.I):
                    matched_seller = msg
                    break
            if matched_seller:
                break
        if not matched_seller:
            for pattern in alternatives:
                for msg in messages:
                    if msg.role == "unknown" and re.search(pattern, msg.text, re.I):
                        matched_unknown = msg
                        break
                if matched_unknown:
                    break
        matched = matched_seller or matched_unknown
        if matched:
            observed_categories.add(category)
            attributed = matched_seller is not None
            signals.append(EvidenceSignal(
                evidence_ref=evidence_ref, source_group=source_group,
                category=f"conversation_{category}", severity=severity if attributed else "context",
                summary=summary if attributed else "Message content resembles a known risk pattern, but the sender role is not established.",
                explanation=("Behavioural pattern observed in a message attributed to the seller by the host importer." if attributed
                             else "The sender role is unknown; treat this only as context until the original conversation identifies who sent it."),
                confidence=confidence if attributed else min(0.45, confidence),
                excerpt=safe_excerpt(matched.text), polarity="risk" if attributed else "context",
                limitations=("Message roles may be mislabelled.", "A phrase can be quoted or used in a legitimate context.", "Conversation patterns do not establish identity or intent."),
                **({"observed_at": matched.timestamp} if matched.timestamp else {}),
            ))

    timeline = []
    for i, msg in enumerate(messages):
        # The timeline intentionally excludes body text and personal identifiers.
        # Buyer/platform messages are not labelled as seller behaviour.
        if msg.role not in {"seller", "unknown"}:
            continue
        categories = [c for c in observed_categories if any(re.search(p, msg.text, re.I) for cat, pats, *_ in _PATTERNS if cat == c for p in pats)]
        if categories:
            timeline.append({"message_index": i, "role": msg.role, "timestamp": msg.timestamp, "events": sorted(categories)})

    return {
        "signals": [s.to_dict() for s in signals],
        "timeline": timeline,
        "message_count": len(messages),
        "seller_message_count": len(seller_texts),
        "unknown_role_message_count": sum(1 for m in messages if m.role == "unknown"),
        "raw_messages_stored": False,
        "limitations": [
            "Timeline analysis uses extracted conversation text only; it cannot authenticate account ownership.",
            "Quoted or forwarded messages may not have been authored by the displayed sender.",
            "No message body is returned or persisted by this component.",
        ],
    }
