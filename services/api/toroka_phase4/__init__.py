"""Toroka Phase 4: autonomous threat-intelligence workflows and safe learning."""
from .content_analysis import ContentAnalysis, ContentSignal, analyze_content
from .campaign import CampaignCase, CampaignCorrelator, CampaignLink
from .intel import (FeedPolicy, IndicatorRecord, ThreatIntelStore, ThreatMatch,
                    default_feed_policies, normalize_indicator, parse_stix21_bundle, refresh_feed)
from .feedback import FeedbackLedger
from .evaluation import (EvaluationCase, EvaluationReport, evaluate,
                         model_release_gate, split_by_campaign)
from .investigator import Phase4Investigator, Phase4Result

__all__ = [
    "ContentAnalysis", "ContentSignal", "analyze_content", "CampaignCase",
    "CampaignCorrelator", "CampaignLink", "FeedPolicy", "IndicatorRecord",
    "ThreatIntelStore", "ThreatMatch", "default_feed_policies",
    "normalize_indicator", "parse_stix21_bundle", "refresh_feed", "FeedbackLedger",
    "EvaluationCase", "EvaluationReport", "evaluate", "model_release_gate",
    "split_by_campaign", "Phase4Investigator", "Phase4Result",
]
