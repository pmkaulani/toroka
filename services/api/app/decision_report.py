"""Deterministic, shopper-facing decision reports for URL/social investigations.

The rules engine remains authoritative: this module maps its existing risk band to
plain-language action guidance and never calculates or changes the risk label.
"""
from __future__ import annotations

import re
from typing import Any

DECISIONS = {
    "high_risk": "dont_pay",
    "suspicious_verify_first": "pause_and_verify",
    "inconclusive": "cant_tell_yet",
    "no_known_threats_found": "pay_only_safely",
    "looks_genuine": "pay_only_safely",
    "verified_official": "pay_only_safely",
}

# Internal statuses are deliberately translated or hidden. Provider configuration is
# not useful information for a shopper and must never leak into the public response.
WHY = {
    "not_configured": None, "disabled": None, "skipped": None, "ok": None,
    "checked": None, "checked_match": None, "checked_no_match": None,
    "not_checked": "this check was not available for this link",
    "blocked_by_platform": "the platform restricts what outside tools can read",
    "login_required": "the page requires a login",
    "timeout": "the check did not finish in time",
    "could_not_check": "the check could not be completed",
    "unreachable": "the website could not be reached",
    "not_found": "the requested page was not found",
    "failed": "the check could not be completed",
    "partial": "only part of this check was completed",
}

PUBLIC_CHECK_NAMES = {
    "safe_web_fetch": "Website content",
    "tavily_search": "Independent public reports",
    "threat_feeds": "Known threat records",
    "google_webrisk": "Website threat records",
    "social_oembed": "Public post details",
    "profile_identity": "Account identity",
    "payment_evidence": "Payment recipient details",
    "business_links": "Business website details",
    "toroka_intel": "Previous Toroka reports",
    "marketplace_product_details": "Marketplace product details",
    "marketplace_seller_verification": "Seller identity",
}

T = {
    "en": {
        "dont_pay": "Do not pay. {who} has serious warning signs.",
        "pause_and_verify": "Pause before paying. Check these warning signs first for {who}.",
        "cant_tell_yet": "I can't tell yet whether {who} is real. Here is how to check before you pay.",
        "pay_only_safely": "I found no known threat indicators for {who}. That is not a guarantee, so use a protected way to pay.",
        "who_account": "this {platform} account (@{handle})",
        "who_site": "this website ({domain})",
        "who_post": "this {platform} post",
        "who_other": "this link",
        "hdr_found": "What I found",
        "hdr_red": "Warning signs",
        "hdr_good": "Positive signs",
        "hdr_unknown": "What I could not check",
        "hdr_before": "Before you pay",
        "hdr_ask": "A message you can send the seller",
        "hdr_paid": "If you already paid",
        "hdr_find": "Five checks you can do yourself",
        "no_advance": "Avoid paying in advance, including a half-payment or booking deposit, until you have independently established who you are paying and what protection you have.",
        "before_2": "Prefer collection or pay-on-delivery after checking the item and seller.",
        "before_3": "For M-PESA, check the recipient name shown before entering your PIN. It should match the business you independently verified.",
        "before_4": "Never share your M-PESA PIN, bank password or one-time code with a seller or anyone claiming to help.",
        "before_5": "Keep screenshots of the advert, conversation, delivery terms and payment request.",
        "ask": "Hi. Before I pay, please share your registered business name, the Till or Paybill name that will appear to me, written delivery and refund terms, and where I can collect the item. Could you also show me the exact item in a short video with today's date? I will verify the details before paying.",
        "paid_1": "Do not send any more money, including extra release, delivery or refund fees.",
        "paid_2": "Contact your bank or mobile-money provider through its official app or published contact details immediately.",
        "paid_3": "Keep the original message, advert, chat, receipt and transaction reference.",
        "paid_4": "Report the account and preserve the case details for the relevant platform and authorities.",
        "unknown_platform": "{platform} restricts what outside tools can read. I could identify the account from the link or public post preview, but I could not independently inspect its followers, comments or full account history.",
        "no_reports": "I did not find independent public reports clearly tied to this exact account in the sources checked. That does not prove it is safe.",
        "no_reviews": "I did not find independent public reports clearly tied to this exact website in the sources checked. That does not prove it is safe.",
        "post_owner_unknown": "This {platform} post link does not reveal the account name. Share the seller's profile link or username so I can investigate who published it.",
        "confidence": "This is an assessment of the information available at the time of checking, not a guarantee.",
    },
    "sw": {
        "dont_pay": "Usilipe. {who} ina dalili kubwa za hatari.",
        "pause_and_verify": "Simama kabla ya kulipa. Kagua dalili hizi za tahadhari kuhusu {who} kwanza.",
        "cant_tell_yet": "Bado siwezi kutambua kama {who} ni halisi. Hivi ndivyo unavyoweza kukagua kabla ya kulipa.",
        "pay_only_safely": "Sikupata viashiria vya tishio vinavyojulikana kuhusu {who}. Hii si hakikisho; tumia njia salama ya malipo.",
        "who_account": "akaunti hii ya {platform} (@{handle})",
        "who_site": "tovuti hii ({domain})",
        "who_post": "chapisho hili la {platform}",
        "who_other": "kiungo hiki",
        "hdr_found": "Nilichopata",
        "hdr_red": "Dalili za hatari",
        "hdr_good": "Dalili nzuri",
        "hdr_unknown": "Nisichoweza kukagua",
        "hdr_before": "Kabla ya kulipa",
        "hdr_ask": "Ujumbe wa kumtumia muuzaji",
        "hdr_paid": "Ikiwa tayari umelipa",
        "hdr_find": "Mambo matano ya kujikagua",
        "no_advance": "Epuka kulipa mapema, hata nusu au amana ya kuhifadhi bidhaa, hadi uthibitishe unayemlipa na ulinzi ulio nao.",
        "before_2": "Pendelea kuchukua bidhaa au kulipa unapopokea baada ya kuikagua.",
        "before_3": "Kwa M-PESA, angalia jina la mpokeaji linaloonekana kabla ya kuweka PIN. Lingane na biashara uliyoithibitisha kivyake.",
        "before_4": "Usimpe muuzaji PIN, nenosiri la benki au msimbo wa uthibitisho.",
        "before_5": "Hifadhi picha za tangazo, mazungumzo, masharti ya uwasilishaji na ombi la malipo.",
        "ask": "Habari. Kabla sijalipa, tafadhali nitumie jina la biashara iliyosajiliwa, jina litakaloonekana kwenye Till au Paybill, masharti ya uwasilishaji na kurejesha pesa kwa maandishi, na mahali pa kuchukua bidhaa. Pia naomba video fupi ya bidhaa halisi ikiwa na tarehe ya leo. Nitathibitisha maelezo kabla ya kulipa.",
        "paid_1": "Usitume pesa zaidi, hata ada ya ziada ya kuachiliwa, usafirishaji au kurejeshewa pesa.",
        "paid_2": "Wasiliana na benki au mtoa huduma wa pesa kupitia programu au mawasiliano yake rasmi mara moja.",
        "paid_3": "Hifadhi ujumbe wa awali, tangazo, mazungumzo, risiti na nambari ya muamala.",
        "paid_4": "Ripoti akaunti hiyo na hifadhi maelezo ya tukio kwa jukwaa na mamlaka husika.",
        "unknown_platform": "{platform} huzuia baadhi ya taarifa kusomwa na zana za nje. Niliweza kutambua akaunti kupitia kiungo au taarifa za chapisho la umma, lakini sikuweza kukagua kivyake wafuasi, maoni au historia kamili ya akaunti.",
        "no_reports": "Sikupata ripoti huru zinazohusishwa wazi na akaunti hii katika vyanzo nilivyokagua. Hilo halithibitishi kuwa ni salama.",
        "no_reviews": "Sikupata ripoti huru zinazohusishwa wazi na tovuti hii katika vyanzo nilivyokagua. Hilo halithibitishi kuwa ni salama.",
        "post_owner_unknown": "Kiungo hiki cha chapisho la {platform} hakionyeshi jina la akaunti. Tuma kiungo cha wasifu wa muuzaji au jina lake la akaunti ili nichunguze aliyechapisha.",
        "confidence": "Huu ni tathmini ya taarifa zilizopatikana wakati wa ukaguzi, si hakikisho.",
    },
}

_NEGATIVE_WORDS = ("scam", "scammer", "fake", "fraud", "tapeli", "conned", "never delivered", "didn't deliver", "did not deliver", "blocked me", "stole", "ripped off", "beware")
_POSITIVE_WORDS = ("delivered", "legit", "genuine", "received my", "trusted seller", "recommend")


def _shopper_text(value: Any) -> str:
    """Remove internal provider/configuration vocabulary from findings shown to users."""
    text = str(value or "")
    text = re.sub(r"(?i)\b(?:not_configured|api_key|api key)\b", "", text)
    text = re.sub(r"(?i)\bTavily\b", "public search", text)
    text = re.sub(r"(?i)\bGemini\b", "AI service", text)
    text = re.sub(r"(?i)\borganisation\b|\borganization\b", "company or service", text)
    return re.sub(r"\s{2,}", " ", text).strip()


def who(facts: dict[str, Any], tr: dict[str, str]) -> str:
    kind = facts.get("kind")
    if kind == "social_account":
        return tr["who_account"].format(platform=(facts.get("platform") or "social").title(), handle=facts.get("handle") or "")
    if kind == "social_post":
        return tr["who_post"].format(platform=(facts.get("platform") or "social").title())
    if kind == "marketplace_listing":
        product_name = facts.get("product", {}).get("name")
        if tr == T["sw"]:
            item = f"bidhaa {product_name} kwenye " if product_name else "tangazo kwenye "
            return f"{item}{facts.get('marketplace_name') or 'jukwaa hili'}"
        item = f"{product_name} on " if product_name else "a listing on "
        return f"{item}{facts.get('marketplace_name') or 'this marketplace'}"
    if facts.get("domain"):
        return tr["who_site"].format(domain=str(facts["domain"]))
    return tr["who_other"]


def plain_unknowns(items: list[dict[str, Any]], platform: str | None, lang: str = "en") -> list[str]:
    output: list[str] = []
    for item in items or []:
        status = str(item.get("status", "could_not_check"))
        why = WHY.get(status, "the check could not be completed")
        if why is None:
            continue
        check_id = str(item.get("id") or "")
        detail = str(item.get("detail") or "").casefold()
        what = PUBLIC_CHECK_NAMES.get(check_id, "Additional information")
        if what == "Additional information" or check_id in {"business_links", "payment_evidence"}:
            continue
        if check_id == "safe_web_fetch" and any(token in detail for token in (
            "blocked:", "private network", "cloud instance metadata", "loopback",
            "link-local", "localhost", "internal hostname", "restricted destination",
        )):
            line = (
                "Website content: I did not open this address because Toroka's safety checks "
                "identified a private or restricted network destination. This restriction is "
                "not evidence that the website is fraudulent."
            )
        elif check_id == "marketplace_seller_verification":
            line = (
                "Utambulisho wa muuzaji: jina au ukadiriaji unaoonyeshwa kwenye tangazo umetolewa na ukurasa; Toroka haijathibitisha muuzaji kivyake."
                if lang == "sw" else
                "Seller identity: the name or rating shown on a marketplace listing is page-provided information; the seller has not been independently verified by Toroka."
            )
        elif check_id == "marketplace_product_details" and status in {"not_checked", "could_not_check", "partial"}:
            line = (
                "Maelezo ya bidhaa: Toroka imetambua jukwaa, lakini haikuweza kusoma au kuthibitisha maelezo yote ya tangazo."
                if lang == "sw" else
                "Product details: Toroka identified the marketplace, but could not read or extract all listing details."
            )
        elif check_id == "safe_web_fetch" and status == "blocked_by_platform":
            line = (
                "Maudhui ya tovuti: tovuti imezuia au kupunguza ukaguzi wa kiotomatiki, kwa hiyo Toroka haikusoma ukurasa. Hii si ushahidi wa ulaghai."
                if lang == "sw" else
                "Website content: the site denied or rate-limited automated inspection, so Toroka did not read the page. This is not evidence of fraud."
            )
        elif check_id == "safe_web_fetch" and status == "not_found":
            line = (
                "Maudhui ya tovuti: ukurasa haukupatikana; Toroka haikuweza kukagua tangazo."
                if lang == "sw" else
                "Website content: the requested page returned a not-found response; Toroka could not inspect the listing."
            )
        elif check_id == "safe_web_fetch" and platform:
            what = "Full profile details"
            line = f"{what}: outside tools may not be able to read this {platform.title()} page"
        elif why == "this check was not available for this link":
            continue
        else:
            line = f"{what}: {why}"
        if line not in output:
            output.append(line)
    return output


def count_mentions(snippets: list[str]) -> dict[str, int]:
    negative = sum(any(word in (snippet or "").lower() for word in _NEGATIVE_WORDS) for snippet in snippets)
    positive = sum(any(word in (snippet or "").lower() for word in _POSITIVE_WORDS) and not any(word in (snippet or "").lower() for word in _NEGATIVE_WORDS) for snippet in snippets)
    return {"total": len(snippets), "negative": negative, "positive": positive}


def _self_checks() -> list[str]:
    return [
        "Open the seller's profile and look at older posts. Check whether the account has a consistent history rather than only recent sales adverts.",
        "Read comments and independent buyer discussions. Look for delivery updates, unresolved complaints or repeated questions about whether items arrived.",
        "Search the exact account name, website domain and public business number together with words such as 'scam' or 'tapeli'.",
        "Ask for a short video of the exact item with today's date, and written delivery, return and refund terms.",
        "Ask for the registered business name and verify it through the official BRS/eCitizen service. A registration record alone does not prove that the social account belongs to that business.",
    ]


def build_decision(facts: dict[str, Any], lang: str = "en") -> dict[str, Any]:
    tr = T.get(lang, T["en"])
    band = str(facts.get("risk_band") or "inconclusive")
    decision = DECISIONS.get(band, "cant_tell_yet")
    found = list(facts.get("found") or [])
    red = list(facts.get("red_flags") or [])
    good = list(facts.get("good_signs") or [])
    mentions = facts.get("mentions")

    if mentions is not None:
        if mentions.get("negative", 0):
            red.append(f"{mentions['negative']} relevant public result(s) contain complaint-related wording. These are leads, not verified findings.")
        elif mentions.get("positive", 0):
            good.append(f"{mentions['positive']} relevant public result(s) contain positive customer wording. These are leads, not verified proof of fulfilment.")
        elif mentions.get("total", 0) == 0:
            if facts.get("kind") == "social_account":
                found.append(tr["no_reports"])
            else:
                found.append(tr["no_reviews"])

    if facts.get("kind") == "social_account" and not facts.get("profile_read"):
        found.append(tr["unknown_platform"].format(platform=(facts.get("platform") or "the platform").title()))
    if facts.get("post_owner_unknown"):
        found.append(tr["post_owner_unknown"].format(platform=(facts.get("platform") or "social").title()))

    # Preserve order while preventing repeated or duplicate provider observations.
    red = list(dict.fromkeys(str(x) for x in red if x))
    good = list(dict.fromkeys(str(x) for x in good if x))
    found = list(dict.fromkeys(str(x) for x in found if x))
    unknowns = plain_unknowns(facts.get("unknowns") or [], facts.get("platform"), lang)

    before = [tr["no_advance"], tr["before_2"], tr["before_3"], tr["before_4"], tr["before_5"]]
    find_steps = _self_checks() if decision in {"cant_tell_yet", "pause_and_verify"} or facts.get("kind") in {"social_account", "social_post"} else []
    if facts.get("post_owner_unknown"):
        find_steps.insert(0, "Share the seller's profile link or username; this post URL alone does not identify the account behind it.")
        find_steps = find_steps[:5]
    if facts.get("risk_band") == "verified_official":
        find_steps = ["This domain matches a current, human-reviewed record from an official source. Open the address by typing it yourself and make sure it is exactly the same before sharing sensitive information."]
    if facts.get("recruitment"):
        before = [
            ("For overseas jobs, verify the recruitment agency and licence through Kenya's National Employment Authority: https://diaspora.go.ke/verify." if lang != "sw" else "Kwa kazi za nje, thibitisha wakala na leseni kupitia Mamlaka ya Kitaifa ya Ajira: https://diaspora.go.ke/verify."),
            "Never pay recruitment, application, medical, visa or processing fees until the employer, vacancy, contract and licensed agency have been independently verified." if lang != "sw" else "Usilipe ada za kuajiriwa, maombi, vipimo, visa au uchakataji hadi mwajiri, nafasi, mkataba na wakala mwenye leseni vithibitishwe kivyake.",
            "If the offer claims to be a U.S. job, independently check the employer's petition and visa process through the official USCIS website: uscis.gov." if lang != "sw" else "Ikiwa kazi inadaiwa kuwa Marekani, hakiki ombi la mwajiri na mchakato wa visa kupitia tovuti rasmi ya USCIS: uscis.gov.",
            "Never share your email password, M-PESA PIN, bank password or one-time code with a recruiter or anyone claiming to help." if lang != "sw" else "Usishiriki nenosiri la barua pepe, PIN ya M-PESA, nenosiri la benki au msimbo wa uthibitisho na mwajiri au mtu yeyote anayesema anakusaidia.",
            "Keep the job advert, recruiter messages, written contract, agency details and any payment requests." if lang != "sw" else "Hifadhi tangazo la kazi, ujumbe wa mwajiri, mkataba wa maandishi, maelezo ya wakala na maombi yote ya malipo.",
        ]
    ask_text = tr["ask"]
    headers = {key: value for key, value in tr.items() if key.startswith("hdr_")}
    if facts.get("recruitment"):
        ask_text = (
            "Hello. Please share the agency's registered legal name, NEA licence number, exact vacancy, named employer, work location, written contract and every fee in writing. I will verify the licence and vacancy independently before sharing documents or paying anything."
            if lang != "sw" else
            "Habari. Tafadhali nitumie jina rasmi la wakala, nambari ya leseni ya NEA, nafasi halisi ya kazi, mwajiri, eneo la kazi, mkataba wa maandishi na ada zote kwa maandishi. Nitathibitisha leseni na nafasi kivyake kabla ya kutuma nyaraka au kulipa."
        )
        headers["hdr_ask"] = "A message you can send the recruiter" if lang != "sw" else "Ujumbe wa kumtumia wakala wa ajira"
    headline = tr[decision].format(who=who(facts, tr))
    official_brand = facts.get("official_brand")
    if official_brand:
        if facts.get("kind") == "marketplace_listing" and facts.get("product", {}).get("name"):
            item = facts["product"]["name"]
            headline = (
                f"This is the real {official_brand} website. I identified {item} on it, but the marketplace does not establish that the seller is trustworthy: check them, and pay only inside {official_brand}."
                if lang != "sw" else
                f"Hii ndiyo tovuti halisi ya {official_brand}. Nimetambua {item} humo, lakini jukwaa halithibitishi uaminifu wa muuzaji: mthibitishe, na ulipe pekee ndani ya {official_brand}."
            )
        else:
            headline = (
                f"This is the real {official_brand} website, but the marketplace does not establish that individual sellers or third-party offers are trustworthy. Pay only inside {official_brand}."
                if lang != "sw" else
                f"Hii ndiyo tovuti halisi ya {official_brand}, lakini jukwaa halithibitishi uaminifu wa wauzaji binafsi au ofa za wengine. Lipa pekee ndani ya {official_brand}."
            )
    elif facts.get("kind") == "marketplace_listing" and decision == "cant_tell_yet":
        item = facts.get("product", {}).get("name")
        if item:
            headline = (
                f"I identified {item} on {facts.get('marketplace_name')}, but the marketplace domain does not establish that its individual seller or listing is trustworthy. Check the seller and keep payment inside the platform."
                if lang != "sw" else
                f"Nimetambua {item} kwenye {facts.get('marketplace_name')}, lakini jina la jukwaa halithibitishi uaminifu wa muuzaji au tangazo hili. Hakiki muuzaji na fanya malipo ndani ya jukwaa."
            )
        else:
            headline = (
                f"I identified the {facts.get('marketplace_name')} marketplace, but the platform does not establish that individual sellers or listings are trustworthy. Check the seller and keep payment inside the platform."
                if lang != "sw" else
                f"Nimetambua soko la {facts.get('marketplace_name')}, lakini jukwaa halithibitishi kuwa wauzaji au matangazo yake ni salama. Hakiki muuzaji na fanya malipo ndani ya jukwaa."
            )
    elif facts.get("kind") == "marketplace_site" and decision == "cant_tell_yet":
        headline = (
            f"I identified the {facts.get('marketplace_name')} marketplace, but the platform does not establish that individual sellers or listings are trustworthy. Check the seller and keep payment inside the platform."
            if lang != "sw" else
            f"Nimetambua soko la {facts.get('marketplace_name')}, lakini jukwaa halithibitishi kuwa wauzaji au matangazo yake ni salama. Hakiki muuzaji na fanya malipo ndani ya jukwaa."
        )
    if facts.get("risk_band") == "verified_official" and facts.get("domain"):
        domain = str(facts["domain"]).lower()
        registrable_label = domain.split(".", 1)[0]
        display_name = registrable_label.upper() if len(registrable_label) <= 4 else registrable_label.capitalize()
        headline = (
            f"This matches a reviewed official record for {display_name} ({domain}). "
            "Use the official site or app directly when sharing information or making payments."
            if lang != "sw" else
            f"Hii inalingana na rekodi rasmi iliyokaguliwa ya {display_name} ({domain}). "
            "Tumia tovuti au programu rasmi moja kwa moja unaposhiriki taarifa au kufanya malipo."
        )
    return {
        "decision": decision,
        "headline": headline,
        "subject": {"kind": facts.get("kind"), "platform": facts.get("platform"), "handle": facts.get("handle"), "domain": facts.get("domain")},
        "marketplace": facts.get("marketplace"),
        "product": facts.get("product") if facts.get("marketplace") else None,
        "found": found,
        "red_flags": red,
        "good_signs": good,
        "could_not_check": unknowns,
        "before_you_pay": before,
        "how_to_find_out": find_steps,
        "ask_the_seller": ask_text,
        "if_you_already_paid": [tr["paid_1"], tr["paid_2"], tr["paid_3"], tr["paid_4"]],
        "headers": headers,
        "confidence_note": tr["confidence"],
    }


def facts_from_result(result: Any, lang: str = "en") -> dict[str, Any]:
    profile = getattr(result, "platform_profile", None)
    platform = getattr(profile, "platform", None)
    handle = getattr(profile, "handle", None) or getattr(profile, "clean_handle", None)
    page_data = getattr(result, "page_data", {}) or {}
    marketplace = page_data.get("marketplace") or {}
    product = marketplace.get("product") or {}
    has_product = bool(product.get("name"))
    official_brand = page_data.get("official_brand")
    kind = (
        "social_account" if platform in {"tiktok", "instagram", "facebook", "x", "whatsapp"} and handle else
        "social_post" if platform in {"tiktok", "instagram", "facebook", "x", "whatsapp"} else
        "marketplace_listing" if marketplace.get("is_marketplace") and has_product else
        "marketplace_site" if marketplace.get("is_marketplace") else
        "shop_site" if getattr(result, "domain", None) else
        "other_site"
    )
    oembed = page_data.get("oembed") or {}
    found = []
    if oembed.get("account_name"):
        found.append(_shopper_text(f"Account name shown by the platform: {str(oembed['account_name'])[:80]}.") )
    if oembed.get("handle"):
        found.append(_shopper_text(f"Account handle shown by the platform: @{str(oembed['handle'])[:50]}.") )
    if oembed.get("caption"):
        found.append(_shopper_text(f"The post's caption says: “{str(oembed['caption'])[:180]}”.") )
    if page_data.get("title"):
        found.append(_shopper_text(f"Website page title: {str(page_data['title'])[:180]}.") )
    if page_data.get("description"):
        found.append(_shopper_text(f"Website description: {str(page_data['description'])[:220]}.") )
    if marketplace.get("is_marketplace"):
        if lang == "sw":
            found.append(_shopper_text(
                f"Jukwaa la mauzo limetambuliwa: {marketplace.get('name')}. Hii inatambua jukwaa pekee; haithibitishi muuzaji au tangazo binafsi."
            ))
            if product.get("name"):
                found.append(_shopper_text(f"Bidhaa inayoonyeshwa kwenye tangazo: {product['name']}."))
            if product.get("price") is not None:
                price = f"{product.get('currency') or 'Bei'} {product['price']:g}"
                found.append(_shopper_text(f"Bei inayoonyeshwa kwenye tangazo: {price}."))
            if product.get("brand"):
                found.append(_shopper_text(f"Chapa inayoonyeshwa: {product['brand']}."))
            if product.get("sku"):
                found.append(_shopper_text(f"Nambari ya bidhaa inayoonyeshwa: {product['sku']}."))
            if product.get("availability"):
                found.append(_shopper_text(f"Upatikanaji unaoonyeshwa: {product['availability']}."))
            if product.get("seller_name"):
                found.append(_shopper_text(f"Jina la muuzaji linaloonyeshwa: {product['seller_name']}. Hili si uthibitisho huru wa utambulisho wa muuzaji."))
            if product.get("seller_rating") is not None:
                found.append(_shopper_text(f"Ukadiriaji wa muuzaji unaoonyeshwa: {product['seller_rating']:g}/5. Ukadiriaji huu haujathibitishwa kivyake."))
            if product.get("aggregate_rating") is not None:
                count = f" kutoka kwa ukadiriaji {product['rating_count']}" if product.get("rating_count") is not None else ""
                found.append(_shopper_text(f"Ukadiriaji wa bidhaa unaoonyeshwa: {product['aggregate_rating']:g}/5{count}. Huu si uthibitisho wa uhalisi au uwasilishaji."))
            if product.get("description"):
                found.append(_shopper_text(f"Maelezo ya bidhaa yaliyoonyeshwa: {product['description'][:300]}."))
            for review in product.get("review_excerpts") or []:
                found.append(_shopper_text(f"Maoni yaliyoonyeshwa kwenye tangazo: “{str(review)[:200]}”. Hayajathibitishwa kivyake."))
        else:
            found.append(_shopper_text(
                f"Marketplace identified: {marketplace.get('name')}. This identifies the hosting platform only; it does not verify the individual seller or listing."
            ))
            if product.get("name"):
                found.append(_shopper_text(f"Product shown on the listing: {product['name']}."))
            if product.get("price") is not None:
                price = f"{product.get('currency') or 'Price'} {product['price']:g}"
                found.append(_shopper_text(f"Price shown on the listing: {price}."))
            if product.get("brand"):
                found.append(_shopper_text(f"Brand shown on the listing: {product['brand']}."))
            if product.get("sku"):
                found.append(_shopper_text(f"Product reference shown: {product['sku']}."))
            if product.get("availability"):
                found.append(_shopper_text(f"Availability shown on the listing: {product['availability']}."))
            if product.get("seller_name"):
                found.append(_shopper_text(f"Seller name shown on the listing: {product['seller_name']}. This is not independent seller verification."))
            if product.get("seller_rating") is not None:
                found.append(_shopper_text(f"Seller rating shown on the listing: {product['seller_rating']:g}/5. This rating has not been independently verified."))
            if product.get("aggregate_rating") is not None:
                count = f" from {product['rating_count']} rating(s)" if product.get("rating_count") is not None else ""
                found.append(_shopper_text(f"Product rating shown on the listing: {product['aggregate_rating']:g}/5{count}. Ratings are displayed-platform data, not proof of authenticity or fulfilment."))
            if product.get("description"):
                found.append(_shopper_text(f"Product description shown: {product['description'][:300]}."))
            for review in product.get("review_excerpts") or []:
                found.append(_shopper_text(f"Review text displayed on the listing: “{str(review)[:200]}”. This has not been independently verified."))
    visible_text = re.sub(r"\s+", " ", str(page_data.get("visible_text_excerpt") or "")).strip()
    if visible_text:
        found.append(_shopper_text(f"Visible text on the website: “{visible_text[:280]}”.") )
    for label, values in (("Phone numbers shown on the page", page_data.get("phones")), ("Email addresses shown on the page", page_data.get("emails")), ("WhatsApp links shown on the page", page_data.get("whatsapp_links")), ("Payment identifiers shown on the page", page_data.get("payment_identifiers"))):
        clean_values = [str(value).strip()[:100] for value in (values or []) if str(value).strip()]
        if clean_values:
            found.append(_shopper_text(f"{label}: {', '.join(clean_values[:5])}.") )

    red = []
    good = []
    for finding in getattr(result, "findings", []) or []:
        strength = str(getattr(finding, "strength", "weak"))
        polarity = getattr(finding, "polarity", "risk")
        if polarity == "positive":
            good.append(_shopper_text(finding.plain_text))
        elif strength in {"strong", "supporting", "Strength.STRONG", "Strength.SUPPORTING"}:
            red.append(_shopper_text(finding.plain_text))
    red.extend(_shopper_text(x) for x in (getattr(result, "contradictions", []) or []))
    coverage = getattr(result, "coverage", []) or []
    unknowns = [{"id": getattr(check, "id", ""), "what": getattr(check, "name", ""), "status": getattr(check, "status", "could_not_check"), "detail": getattr(check, "detail", "")} for check in coverage]
    return {
        "kind": kind, "platform": platform, "handle": handle, "domain": getattr(result, "domain", None),
        "official_brand": official_brand,
        "marketplace": {"name": marketplace.get("name"), "page_read": marketplace.get("page_read", False), "seller_detected": marketplace.get("seller_detected", False)} if marketplace.get("is_marketplace") else None,
        "marketplace_name": marketplace.get("name"),
        "product": {key: product.get(key) for key in ("detected", "extraction_status", "name", "description", "brand", "sku", "price", "currency", "availability", "seller_name", "seller_rating", "aggregate_rating", "rating_count", "review_count", "delivery_terms_found", "return_terms_found")},
        "risk_band": getattr(result, "risk_band", "inconclusive"), "red_flags": red, "good_signs": good,
        "found": found, "unknowns": unknowns, "mentions": page_data.get("mentions"),
        # Post oEmbed is not a profile inspection; followers, comments and account
        # history remain unknown even when author/caption metadata is available.
        "profile_read": False,
        "recruitment": any(str(getattr(f, "code", "")).startswith("RECRUITMENT_") for f in (getattr(result, "findings", []) or [])),
        "post_owner_unknown": kind == "social_post" and not handle,
        "language": lang,
    }


def ai_text_ok(text: str, decision: str) -> bool:
    """Reject an AI rewording that contradicts the rules-engine decision or accuses a person."""
    value = (text or "").casefold()
    if re.search(r"\b(?:is|looks|seems|appears)\s+(?:completely\s+)?(?:safe|legitimate|legit|genuine|trustworthy)\b", value):
        if decision in {"dont_pay", "pause_and_verify"}:
            return False
    if any(phrase in value for phrase in ("go ahead and pay", "you can safely pay", "no need to worry", "is a scammer", "is scamming", "definitely a scam")):
        return False
    return True
