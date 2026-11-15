"""Self-contained HTML investigation report for one lead: facts, inferences, gaps, alternative explanations, provenance.

Input is the pseudonymised lead (and optional run manifest). Every dynamic string is escaped. Nothing here names a person.
"""
from __future__ import annotations

import html
from datetime import datetime, timedelta, timezone

EAT = timezone(timedelta(hours=3))
POL = {"risk": ("Unexplained", "var(--risk)"), "support": ("Explains / supports", "var(--ok)"), "context": ("Context / not assessable", "var(--mute)")}


def esc(v) -> str:
    return html.escape(str(v if v is not None else ""), quote=True)


def _when(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso).astimezone(EAT).strftime("%d %b %Y, %H:%M EAT")
    except (TypeError, ValueError):
        return esc(iso)


def _evidence(lead: dict) -> list[dict]:
    out = [e for k in ("risk_evidence", "supporting_evidence", "context_evidence") for e in lead.get(k, [])]
    return sorted(out, key=lambda e: e["observed_at"])


def _map_svg(lead: dict, evidence: list[dict]) -> str:
    groups: dict[tuple[str, str], int] = {}
    for e in evidence:
        groups[(e["source_group"], e["polarity"])] = groups.get((e["source_group"], e["polarity"]), 0) + 1
    rows = sorted(groups.items(), key=lambda kv: (kv[0][1] != "risk", kv[0][0]))
    h = max(120, 46 * len(rows) + 30)
    parts = [f'<svg viewBox="0 0 720 {h}" role="img" aria-label="Evidence map: independent record sources pointing at this lead" xmlns="http://www.w3.org/2000/svg">']
    cy = h / 2
    parts.append(f'<rect x="10" y="{cy - 28}" width="210" height="56" rx="10" fill="none" stroke="currentColor"/>'
                 f'<text x="115" y="{cy - 4}" text-anchor="middle" font-size="13">{esc(lead.get("staff_ref", ""))}</text>'
                 f'<text x="115" y="{cy + 14}" text-anchor="middle" font-size="12" opacity=".75">{esc(lead.get("customer_ref") or "staff-level focus")}</text>')
    for i, ((group, pol), n) in enumerate(rows):
        y = 30 + 46 * i
        colour = POL[pol][1]
        parts.append(f'<line x1="220" y1="{cy}" x2="470" y2="{y}" stroke="{colour}" stroke-width="2"/>'
                     f'<rect x="470" y="{y - 18}" width="240" height="36" rx="8" fill="none" stroke="{colour}" stroke-width="2"/>'
                     f'<text x="482" y="{y + 5}" font-size="13">{esc(group)} · {n} · {esc(POL[pol][0])}</text>')
    parts.append("</svg>")
    return "".join(parts)


def render_case(lead: dict, manifest: dict | None = None) -> str:
    ev = _evidence(lead)
    rows = "".join(
        f'<tr><td>{_when(e["observed_at"])}</td><td>{esc(e["source"])}<br><small>{esc(e["source_group"])}</small></td>'
        f'<td><span class="chip" style="border-color:{POL[e["polarity"]][1]};color:{POL[e["polarity"]][1]}">{esc(POL[e["polarity"]][0])}</span></td>'
        f'<td>{esc(e["summary"])}<br><small>{esc(", ".join(e["metadata"].get("record_refs", [])))}</small></td></tr>' for e in ev)
    inferences = "".join(f"<li>{esc(e['why_it_matters'])}</li>" for e in lead.get("risk_evidence", []) if e.get("why_it_matters"))
    gaps = [f"Check not run: {c.replace('_', ' ')} (its source feed was not supplied)." for c in lead.get("unavailable_checks", [])]
    gaps += [e["summary"] for e in lead.get("context_evidence", [])] + [x for x in lead.get("limitations", [])]
    alternatives = [e["summary"] for e in lead.get("supporting_evidence", [])]
    alt_lim = []
    for e in lead.get("risk_evidence", []):
        alt_lim += e.get("limitations", [])
    li = lambda items: "".join(f"<li>{esc(i)}</li>" for i in items) or "<li>None recorded.</li>"
    prov = ""
    if manifest:
        files = "".join(f"<tr><td>{esc(feed)}</td><td>{esc(f['file'])}</td><td><code>{esc(f['sha256'][:16])}…</code></td></tr>" for feed, fs in manifest["inputs"].items() for f in fs)
        prov = (f'<h2>Provenance</h2><p>Run <code>{esc(manifest["manifest_id"])}</code> · tool {esc(manifest["tool_version"])} · profile {esc(manifest["profile"])} · '
                f'ingested {_when(manifest["ingested_at"])} · mapping <code>{esc(manifest["mapping_sha256"][:16])}</code> · scoring policy <code>{esc(manifest["scoring_policy_sha256"][:16])}</code></p>'
                f'<p>A record is identified by feed, file hash and row number, as cited in the table above.</p>'
                f'<table><tr><th>Feed</th><th>Source file</th><th>SHA-256 (start)</th></tr>{files}</table>')
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Investigation report · {esc(lead.get("focus"))}</title><style>
:root{{--bg:#fff;--fg:#1a1a1a;--mute:#666;--line:#ddd;--risk:#b3261e;--ok:#1b6e3c;--card:#f7f7f5}}
@media (prefers-color-scheme: dark){{:root{{--bg:#16181a;--fg:#ececec;--mute:#a0a0a0;--line:#3a3d40;--risk:#ff8a80;--ok:#7ddc9e;--card:#1f2224}}}}
body{{font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--bg);color:var(--fg);max-width:900px;margin:0 auto;padding:24px 18px 60px}}
h1{{font-size:22px;margin:0 0 4px}}h2{{font-size:16px;margin:28px 0 8px;border-bottom:1px solid var(--line);padding-bottom:4px}}
.banner{{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--risk);padding:10px 14px;border-radius:6px;margin:14px 0}}
table{{border-collapse:collapse;width:100%;display:block;overflow-x:auto}}td,th{{border-bottom:1px solid var(--line);padding:7px 8px;text-align:left;vertical-align:top;font-size:14px}}
small{{color:var(--mute)}}.chip{{border:1px solid;border-radius:999px;padding:1px 8px;font-size:12px;white-space:nowrap}}code{{font-size:13px}}
.kpi span{{display:inline-block;margin-right:22px}}svg{{max-width:100%;color:var(--fg)}}.sign td{{height:34px}}@media print{{body{{padding:0}}}}
</style></head><body>
<h1>{esc(lead.get("label"))} · {esc(lead.get("focus"))}</h1>
<p class="kpi"><span><b>Signal index</b> {esc(lead.get("risk_index"))}</span><span><b>Confidence</b> {esc(lead.get("confidence"))}</span><span><b>Verdict key</b> {esc(lead.get("verdict"))}</span></p>
<div class="banner"><b>An investigative lead, not a finding.</b> It was produced by automated checks on the supplied records. It does not establish misconduct by any person. Identities are pseudonymised; revealing one needs a written reason and a second authoriser.</div>
<h2>Assessment</h2><p>{esc(lead.get("conclusion"))}</p><p><small>{esc(lead.get("risk_index_note"))} {esc(lead.get("confidence_note"))}</small></p>
<h2>Evidence map</h2>{_map_svg(lead, ev)}
<h2>What the records show (chronological)</h2><table><tr><th>When</th><th>Source</th><th>Reading</th><th>Record</th></tr>{rows}</table>
<h2>What this suggests (inference, not fact)</h2><ul>{inferences or "<li>No risk inference was drawn.</li>"}</ul>
<h2>What could not be checked or is uncertain</h2><ul>{li(gaps)}</ul>
<h2>Alternative explanations to rule out</h2><p>Records that point to a legitimate explanation:</p><ul>{li(alternatives)}</ul><p>Innocent explanations the checks themselves flag:</p><ul>{li(alt_lim)}</ul>
<h2>Suggested next steps</h2><ul>{li(lead.get("recommended_actions", []))}</ul>
{prov}
<h2>Reviewer record</h2><table class="sign"><tr><td>Alternative explanations considered</td><td></td></tr><tr><td>Disposition</td><td></td></tr><tr><td>Investigator · date</td><td></td></tr><tr><td>Second reviewer · date</td><td></td></tr></table>
</body></html>"""
