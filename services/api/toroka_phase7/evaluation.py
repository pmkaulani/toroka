from __future__ import annotations
import hashlib
from collections import defaultdict
from .multilingual import analyze_message


def campaign_group_split(samples: list[dict], *, test_fraction: float=0.25) -> tuple[list[dict],list[dict]]:
    """Deterministic campaign-level split: one campaign can never leak across partitions."""
    if not 0.05 <= test_fraction <= 0.5: raise ValueError("test_fraction must be between 0.05 and 0.5")
    campaigns=sorted({str(row.get("campaign_id","")) for row in samples})
    if any(not c for c in campaigns): raise ValueError("every sample needs a campaign_id")
    test_campaigns={c for c in campaigns if int(hashlib.sha256(c.encode()).hexdigest()[:8],16)/0xFFFFFFFF < test_fraction}
    # Guarantee a non-empty test set when at least two campaigns are present.
    if len(campaigns)>1 and not test_campaigns:
        test_campaigns={campaigns[-1]}
    train=[r for r in samples if str(r["campaign_id"]) not in test_campaigns]
    test=[r for r in samples if str(r["campaign_id"]) in test_campaigns]
    return train,test


def _metrics(rows):
    tp=sum(r["predicted"] and r["actual"] for r in rows)
    fp=sum(r["predicted"] and not r["actual"] for r in rows)
    tn=sum(not r["predicted"] and not r["actual"] for r in rows)
    fn=sum(not r["predicted"] and r["actual"] for r in rows)
    precision=tp/(tp+fp) if tp+fp else 0.0
    recall=tp/(tp+fn) if tp+fn else 0.0
    specificity=tn/(tn+fp) if tn+fp else 0.0
    fpr=fp/(fp+tn) if fp+tn else 0.0
    f1=2*precision*recall/(precision+recall) if precision+recall else 0.0
    return {"samples":len(rows),"tp":tp,"fp":fp,"tn":tn,"fn":fn,"precision":round(precision,4),"recall":round(recall,4),"specificity":round(specificity,4),"false_positive_rate":round(fpr,4),"f1":round(f1,4)}


def evaluate_rule_set(samples: list[dict]) -> dict:
    evaluated=[]
    for row in samples:
        if not isinstance(row.get("text"),str) or row.get("label") not in {"scam","legitimate"}:
            raise ValueError("sample requires text and scam/legitimate label")
        if not row.get("campaign_id"): raise ValueError("sample requires campaign_id")
        result=analyze_message(row["text"])
        evaluated.append({"predicted":bool(result.signals),"actual":row["label"]=="scam","language":row.get("language") or result.language,"campaign_id":str(row["campaign_id"])})
    by_language=defaultdict(list)
    for row in evaluated: by_language[row["language"]].append(row)
    return {"overall":_metrics(evaluated),"by_language":{lang:_metrics(rows) for lang,rows in sorted(by_language.items())},
            "campaign_count":len({r["campaign_id"] for r in evaluated}),
            "limitations":["Metrics are only as representative as the supplied labelled sample.","Synthetic fixtures are software tests, not production performance evidence.","Campaign-grouped splits are required to reduce near-duplicate leakage."]}


def shadow_release_gate(metrics: dict, *, min_samples: int=200, min_campaigns: int=40,
                        min_precision: float=0.97, min_recall: float=0.90, max_fpr: float=0.02,
                        required_languages: tuple[str,...]=( "en", "sw", "sheng" ),
                        min_language_samples: int=30, language_min_precision: float=0.95,
                        language_min_recall: float=0.85, language_max_fpr: float=0.03) -> dict:
    overall=metrics.get("overall",{})
    checks={"minimum_samples":overall.get("samples",0)>=min_samples,
            "minimum_campaigns":metrics.get("campaign_count",0)>=min_campaigns,
            "precision":overall.get("precision",0)>=min_precision,
            "recall":overall.get("recall",0)>=min_recall,
            "false_positive_rate":overall.get("false_positive_rate",1)<=max_fpr}
    language_checks={}
    by_language=metrics.get("by_language",{})
    for lang in required_languages:
        row=by_language.get(lang,{})
        language_checks[lang]={
            "minimum_samples":row.get("samples",0)>=min_language_samples,
            "precision":row.get("precision",0)>=language_min_precision,
            "recall":row.get("recall",0)>=language_min_recall,
            "false_positive_rate":row.get("false_positive_rate",1)<=language_max_fpr,
        }
    checks["language_subgroups"] = all(all(group.values()) for group in language_checks.values())
    passed=all(checks.values())
    return {"passed":passed,"checks":checks,"language_checks":language_checks,
            "authorization":"shadow_only" if passed else "blocked",
            "production_promotion_allowed":False,
            "note":"Passing permits shadow evaluation only. Every required language must meet its minimum sample and quality gates. Human approval and a separate deployment gate are still required."}
