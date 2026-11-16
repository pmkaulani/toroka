"""Last line of defence: nothing internal reaches a person, whichever code path wrote the sentence."""
import re

INTERNAL = re.compile(r"(?i)(tavily|scrape ?creators?|weir|urlscan|virustotal|google places|gemini|openai|api[_ ]?key|not[_ ]configured|breaker|provider|in this run|toroka internal intelligence|\b[A-Z_]{4,}_KEY\b)")


def scrub_reply(text: str) -> str:
    """Drops whole sentences or bullet lines that mention internals, then tidies the spacing."""
    if not text:
        return text
    out = []
    for line in text.split("\n"):
        parts = re.split(r"(?<=[.!?])\s+", line)
        kept = [p for p in parts if not INTERNAL.search(p)]
        if kept:
            out.append(" ".join(kept))
        elif not line.strip():
            out.append("")
    return re.sub(r"\n{3,}", "\n\n", "\n".join(out)).strip()
