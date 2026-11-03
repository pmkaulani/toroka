"""Locations are claims with provenance, never a trust signal on their own (blueprint 4.6).

No device GPS is ever used. We only read places the message or evidence itself claims.
"""
from __future__ import annotations

import re

COUNTIES = ["Mombasa", "Kwale", "Kilifi", "Tana River", "Lamu", "Taita-Taveta", "Garissa", "Wajir", "Mandera", "Marsabit", "Isiolo",
            "Meru", "Tharaka-Nithi", "Embu", "Kitui", "Machakos", "Makueni", "Nyandarua", "Nyeri", "Kirinyaga", "Murang'a", "Kiambu",
            "Turkana", "West Pokot", "Samburu", "Trans-Nzoia", "Uasin Gishu", "Elgeyo-Marakwet", "Nandi", "Baringo", "Laikipia", "Nakuru",
            "Narok", "Kajiado", "Kericho", "Bomet", "Kakamega", "Vihiga", "Bungoma", "Busia", "Siaya", "Kisumu", "Homa Bay", "Migori",
            "Kisii", "Nyamira", "Nairobi"]
TOWN_TO_COUNTY = {"Eldoret": "Uasin Gishu", "Thika": "Kiambu", "Ruiru": "Kiambu", "Kikuyu": "Kiambu", "Kitale": "Trans-Nzoia",
                  "Naivasha": "Nakuru", "Nanyuki": "Laikipia", "Rongai": "Kajiado", "Ngong": "Kajiado", "Kitengela": "Kajiado",
                  "Athi River": "Machakos", "Malindi": "Kilifi", "Voi": "Taita-Taveta", "Lodwar": "Turkana", "Kapenguria": "West Pokot",
                  "Kapsabet": "Nandi", "Nyahururu": "Laikipia", "Kisumu": "Kisumu", "Mtwapa": "Kilifi", "Ukunda": "Kwale",
                  "Mumias": "Kakamega", "Webuye": "Bungoma", "Kehancha": "Migori", "Awendo": "Migori"}
_PLACES = {**{c: c for c in COUNTIES}, **TOWN_TO_COUNTY}
_PLACE_RE = re.compile(r"(?i)(?<![\w])(" + "|".join(sorted((re.escape(p) for p in _PLACES), key=len, reverse=True)) + r")(?![\w])")


def extract_location_claims(text: str) -> list[tuple[str, str]]:
    """[(place as written, county)] in order of appearance, de-duplicated by county."""
    seen, out = set(), []
    for m in _PLACE_RE.finditer(text):
        key = next(k for k in _PLACES if k.lower() == m.group(1).lower())
        county = _PLACES[key]
        if county not in seen:
            seen.add(county)
            out.append((m.group(1), county))
    return out


def counties_by_piece(pieces: dict[str, str]) -> dict[str, set[str]]:
    return {label: {c for _, c in extract_location_claims(t)} for label, t in pieces.items() if extract_location_claims(t)}
