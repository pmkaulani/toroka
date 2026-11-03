import os
import sys
from pathlib import Path

ROOT = Path(__file__).parents[3]
sys.path.insert(0, str(ROOT / "eval"))
import run_eval


def test_shipped_eval_cases_pass_the_policy_thresholds(capsys):
    assert run_eval.main(["--cases", str(ROOT / "eval" / "cases.csv")]) == 0
    s = run_eval.summarise(run_eval.run(str(ROOT / "eval" / "cases.csv")))
    assert s["legit_high_risk"] == 0 and s["legit_flagged_rate"] == 0 and s["accusatory_wording"] == 0 and not s["mismatches"]
