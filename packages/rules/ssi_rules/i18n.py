"""Swahili result copy (DRAFT: needs review by native speakers before launch; see research plan).

Anything without a translation falls back to English, and the response says so.
"""
from __future__ import annotations

import copy

LABELS = {
    "en": {"high_risk": "High risk", "suspicious_verify_first": "Suspicious: verify first", "inconclusive": "Inconclusive", "no_known_threats_found": "No known threats found", "verified_official": "Verified"},
    "sw": {"high_risk": "Hatari kubwa", "suspicious_verify_first": "Una shaka: thibitisha kwanza", "inconclusive": "Haijathibitika", "no_known_threats_found": "Hakuna tishio linalojulikana", "verified_official": "Imethibitishwa"},
}
SUMMARY_SW = {
    "high_risk": "Hatari kubwa. {lead} Usilipe wala kutuma chochote hadi uthibitishe na shirika husika mwenyewe.",
    "suspicious_verify_first": "Una shaka. Thibitisha kwanza. {lead} Hii si ushahidi wa ulaghai, na baadhi ya mashirika halali huomba mambo kama haya.",
    "inconclusive": "Hatukuweza kuthibitisha kwa vyovyote vile. {lead}",
    "no_known_threats_found": "Hakuna tishio linalojulikana katika ukaguzi tuliofanya. Hilo si hakikisho kwamba ujumbe ni halali.",
    "verified_official": "Imethibitishwa. {lead} Hii ina maana utambulisho wa tovuti ulilingana na chanzo kilichokaguliwa, si kwamba kila ofa au ujumbe kwa jina lake ni halali. Thibitisha ofa husika na mpokeaji wa malipo.",
}
FINDINGS_SW = {
    "ADVANCE_PAYMENT_REQUEST": ("Ujumbe unakuomba ulipe mapema, hata kidogo.", "Kulipa kabla ya kupokea bidhaa, hata nusu, ndiyo njia ya kawaida ya watu kupoteza pesa kwa maduka bandia. Hata biashara halisi inaweza kunakiliwa."),
    "VERIFIED_OFFICIAL_SITE": ("Hii ni tovuti rasmi iliyothibitishwa.", "Imethibitishwa kutoka kwa chanzo kilichoonyeshwa. Tovuti halisi haimaanishi kila ujumbe au ofa kwa jina lake ni halisi."),
    "PIN_OR_OTP_REQUEST": ("Ujumbe unakuomba utume PIN, nenosiri au msimbo wa mara moja.",
                           "Benki, watoa huduma wa pesa za simu na ofisi za serikali hawahitaji utume msimbo wa siri kwa ujumbe au simu."),
    "ADVANCE_FEE_REQUEST": ("Ujumbe unaomba pesa mapema kabla ya kupokea kitu.",
                            "Kulipa mapema ni ishara ya tahadhari. Baadhi ya mashirika halali hutoza ada, kwa hivyo hatukuweza kuthibitisha kama hii ni sehemu ya utaratibu rasmi."),
    "PRIZE_OR_BENEFIT_CLAIM": ("Ujumbe unasema umeshinda au umechaguliwa kupata kitu.",
                               "Zawadi na programu halisi zipo, kwa hivyo hili pekee halithibitishi lolote. Lina uzito likiunganishwa na ombi la malipo au kiungo."),
    "URGENCY_PRESSURE": ("Ujumbe unakusukuma ufanye haraka.", "Shinikizo la haraka ni la kawaida katika ulaghai na pia katika vikumbusho halali, kwa hivyo ni ishara dhaifu tu."),
    "WRONG_TRANSFER_REVERSAL": ("Ujumbe unasema pesa zilitumwa kwako kimakosa na unaomba zirudishwe.",
                                "Ujumbe bandia wa 'nimetuma kimakosa' ni mbinu inayojulikana. Angalia salio lako kwa SMS au kwenye programu ya M-PESA kabla ya kutuma chochote."),
    "SHORTENED_URL": ("Ujumbe unatumia kiungo kifupi, kwa hivyo mahali kinapoelekea hapajulikani.", "Watumaji halali pia hutumia viungo vifupi. Mahali kiungo kinapoelekea hapajakaguliwa hapa."),
    "PAYMENT_TO_MOBILE_NUMBER": ("Ujumbe unakuomba utume pesa kwa nambari ya simu ya kawaida.",
                                 "Wauzaji wengi halali hutumia nambari za kibinafsi. Ni sababu ya kuthibitisha mmiliki wa nambari kabla ya kulipa."),
    "LOOKALIKE_DOMAIN": ("Kiungo kinatumia jina la shirika lakini si anwani rasmi tuliyo nayo.", "Fungua tovuti rasmi kwa kuandika anwani mwenyewe."),
    "OFFICIAL_DOMAIN_MISMATCH": ("Ujumbe unataja shirika lakini unaelekeza tovuti nyingine.", "Fungua tovuti rasmi kwa kuandika anwani mwenyewe."),
    "OFFICIAL_SOURCE_NOT_FOUND": ("Hatukuweza kuthibitisha programu au nafasi hii kutoka chanzo rasmi tulichonacho.",
                                  "Kutopatikana si ushahidi kwamba haipo. Tafuta tovuti rasmi mwenyewe na uone kama nafasi hiyo ipo."),
    "THREAT_FEED_MATCH": ("Kiungo kinalingana na orodha ya vitisho inayojulikana.", "Orodha hizi si kamili, lakini kulingana nazo ni ushahidi mzito kwamba ukurasa una madhara."),
    "GUARANTEED_RETURNS": ("Ujumbe unaahidi faida ya uhakika au ya juu kupita kawaida.", "Uwekezaji halali hauwezi kuhakikisha faida. Angalia kama mtoaji ana leseni kupitia mdhibiti husika."),
    "REPORTED_FRAUD_INCIDENT": ("Umeripoti kutuma pesa bila kupokea bidhaa au kulaghaiwa.", "Kutotuma mzigo baada ya malipo ndiyo mbinu kuu ya ulaghai wa ununuzi mtandaoni nchini Kenya. Usitume pesa zaidi za 'kusafirisha' au 'kutoa mzigo'. Chukua hatua za kurejesha pesa mara moja."),
    "TASK_SCAM_LURE": ("Ujumbe unashawishi kupata pesa kwa kazi rahisi za mtandaoni.", "Miradi ya kulipwa kwa kubofya au kutazama video mara nyingi ni ulaghai. Hukupa pesa kidogo mwanzoni kisha kuitisha ada ya kujiunga."),
    "RECRUITMENT_PERSONAL_CHANNEL": ("Ofa ya kazi inaelekeza kutuma maombi kwenye nambari binafsi ya WhatsApp.", "Mashirika halali hutumia tovuti rasmi za ajira badala ya nambari binafsi za WhatsApp."),
    "PRICE_OUTLIER_RISK": ("Bei ya bidhaa ya thamani ya juu iko chini isivyo kawaida.", "Walaghai hutangaza vifaa vya bei ghali kwa punguzo lisilowezekana ili kushawishi watu watume amana."),
    "MPESA_SMS_NOTICE": ("Ujumbe umeundwa kama SMS ya uthibitisho wa M-PESA.", "Ujumbe wa SMS unaweza kughushiwa. Daima thibitisha salio kwa *334# au programu ya M-PESA kabla ya kurejesha au kutoa mzigo."),
    "FAKE_INVOICE_GENERATOR": ("Maandishi yana jina la kiolezo cha ankara au nambari ya mwanzo ya mfano.", "Majina ya violezo na nambari zinazofuatana zinaweza pia kuonekana kwenye ankara halali. Thibitisha mtoaji na kama kuna ombi la kulipa ada ili kufungua malipo yaliyoahidiwa."),
    "REDEMPTION_PAYOUT_TRAP": ("Maandishi yanatumia neno 'redemption' pamoja na maelezo yanayofanana na ankara au fedha za kigeni.", "Neno 'redemption' au fedha za kigeni pekee hazithibitishi utapeli. Ombi la ada ya mapema ili kufungua malipo yaliyoahidiwa ni ishara muhimu zaidi."),
    "GAMBLING_BONUS_PROMOTION": ("Ujumbe unaonekana kutangaza ofa ya kamari au kasino.", "Maneno ya ofa pekee hayaonyeshi kama ujumbe ni wa utapeli au halali. Thibitisha mtumaji, tovuti halisi, masharti ya ofa na ombi lolote la pesa au taarifa za siri. Kamari ni kwa watu wazima na inaweza kusababisha hasara."),
    "DIPLOMATIC_PARCEL_CUSTOMS_TRAP": ("Ombi la ada ya kutoa kifurushi cha kidiplomasia au forodha ya JKIA.", "Mbinu maarufu ya matapeli wanaodai wametuma zawadi kutoka ng'ambo kisha mtu anapiga simu akidai ada ya forodha. KRA haitozi ushuru kwa nambari binafsi."),
    "ADVANCE_DELIVERY_FEE_TRAP": ("Muuzaji anakataa malipo baada ya kupokea na kusisitiza ada ya rider kabla ya kutuma.", "Kudai ada ya usafirishaji kabla ya kuona mzigo ndiyo mbinu kuu ya maduka feki ya mtandaoni nchini Kenya."),
    "VIEWING_FEE_TRAP": ("Ombi la ada ya kuona nyumba (viewing fee) kabla ya kukagua chumba au nyumba.", "Macaretaker halali hawatozi ada ya kuona nyumba. Walaghai huiba picha za nyumba nzuri na kuitisha pesa za mafuta."),
    "RECRUITMENT_UNNAMED_EMPLOYER": ("Hakuna mwajiri halisi aliyetajwa", "Matangazo halali ya kazi hutaja jina kamili la kampuni inayoomba wafanyakazi, mahali ilipo na mawasiliano rasmi."),
    "RECRUITMENT_NO_VACANCY_DETAILS": ("Hakuna maelezo kamili ya kazi au nafasi husika", "Matangazo halali hufafanua wajibu na jina la kazi badala ya kukuambia ujisajili bila nafasi maalum kutajwa."),
    "RECRUITMENT_IMPLAUSIBLE_IMMIGRATION": ("Njia ya kibali cha kufanya kazi Marekani haijathibitishwa", "Kufanya kazi Marekani kunahitaji mwajiri aliyesajiliwa kuwasilisha ombi rasmi kwa USCIS (uscis.gov) kabla ya visa kutolewa. Cheti cha kidato cha nne pekee hakitoi kibali cha kufanya kazi Marekani."),
    "RECRUITMENT_UNLICENSED_AGENCY": ("Hakuna leseni ya wakala wa ajira ya NEA iliyotolewa", "Sheria ya Kenya inahitaji mashirika yanayosajili watu kwenda ng'ambo kuwa na leseni ya National Employment Authority (NEA) inayoweza kuthibitishwa kupitia diaspora.go.ke/verify."),
    "RECRUITMENT_SUSPICIOUS_PORTAL": ("Maombi ya kazi yanaelekezwa kwenye tovuti isiyolingana", "Kiungo kinaelekeza kwenye tovuti ya jumla badala ya tovuti rasmi ya ajira ya kampuni au wakala aliyeidhinishwa."),
    "RANDOM_URL_PATH_PATTERN": ("Kiungo chenye herufi nasibu za njia ya URL", "Anwani inatumia njia nasibu ya herufi, muundo unaotumiwa mara kwa mara katika viungo vya hadaa ya mtandaoni."),
    "RECRUITMENT_APPLICATION_FEE": ("Ombi la ada ya maombi au usajili wa kazi", "Waajiri halali na mawakala wa maadili hawatoi wala kutoza ada ya maombi kabla ya mkataba wa kazi kuthibitishwa."),
    "RECRUITMENT_DOMAIN_PHISHING_HISTORY": ("Kikoa kinahusishwa na kampuni ya hadaa ya ajira iliyonakiliwa", "Kikoa hiki kimeripotiwa katika kumbukumbu za vitisho kama jukwaa la kuiba taarifa za siri za watafuta kazi."),
    "DOCUMENTED_CAMPAIGN_MATCH": ("Kikoa kinalingana na ripoti ya kampeni ya ulaghai", "Kikoa hiki kimerekodiwa katika hifadhidata ya ripoti za ulaghai."),
    "DOMAIN_REPUTATION_HIGH_RISK": ("Ukaguzi wa kikoa unaonyesha hatari kubwa", "Vyanzo vya usalama na kingavirusi vimeorodhesha kikoa hiki kuwa hatari."),
}
NEXT_STEPS_SW = {
    "Open the organisation's official website by typing its address yourself and look for the same vacancy. Do not use links from the message.":
        "Fungua tovuti rasmi ya shirika kwa kuandika anwani mwenyewe na utafute nafasi hiyo hiyo. Usitumie viungo vilivyo kwenye ujumbe.",
    "Never share email passwords, OTPs, or M-PESA PINs. Legitimate employers never ask for your account password.":
        "Usishiriki nenosiri la barua pepe, OTP, au PIN ya M-PESA kamwe. Waajiri halali hawaombi nenosiri la akaunti yako.",
    "Never pay upfront application, registration, medical, visa or processing fees before contracts are confirmed.":
        "Usilipe kamwe ada ya maombi, usajili, matibabu, visa au usindikaji kabla ya mikataba kuthibitishwa.",
    "Verify recruitment agencies and foreign employment permits with the National Employment Authority (NEA) via diaspora.go.ke/verify.":
        "Thibitisha mawakala wa ajira na vibali vya kazi za nje na Mamlaka ya Kitaifa ya Ajira (NEA) kupitia diaspora.go.ke/verify.",
    "For US employment, an authorized employer must file an approved petition with USCIS (uscis.gov) before a work visa can be issued.":
        "Kwa ajira ya Marekani, mwajiri aliyeidhinishwa lazima awasilishe ombi lililoidhinishwa kwa USCIS (uscis.gov) kabla ya visa ya kazi kutolewa.",
    "Before sending money, independently verify the seller, payment recipient, delivery terms, and any available buyer protection. Advance payment can be legitimate; pressure, contradictory details, or an unverifiable recipient are stronger warning signs.":
        "Kabla ya kutuma pesa, thibitisha muuzaji, mpokeaji wa malipo, masharti ya usafirishaji na ulinzi wowote wa mnunuzi kupitia njia huru. Malipo ya mapema yanaweza kuwa halali; shinikizo, maelezo yanayokinzana au mpokeaji asiyethibitishika ni ishara muhimu zaidi za tahadhari.",
    "Do not pay or reply yet. Contact the organisation using a website or number you look up yourself, not the one in the message.":
        "Usilipe wala kujibu bado. Wasiliana na shirika kwa kutumia tovuti au nambari uliyoitafuta mwenyewe, si ile iliyo kwenye ujumbe.",
    "Ask the sender for details and confirm with the organisation through its official channels before acting.":
        "Mwombe mtumaji maelezo zaidi na uthibitishe na shirika kupitia njia zake rasmi kabla ya kuchukua hatua.",
    "Never share a PIN or one-time code. If you already did, contact your provider now using the number on its official website or app.":
        "Usishiriki PIN wala msimbo wa mara moja kamwe. Ikiwa tayari umeshiriki, wasiliana na mtoaji wako sasa kwa nambari iliyo kwenye tovuti au programu yake rasmi.",
    "Stop all further payments to this seller. Do not pay any extra 'delivery', 'customs', or 'clearance' fees.":
        "Sitisha malipo yote zaidi kwa muuzaji huyu. Usilipe ada yoyote ya ziada ya 'usafirishaji', 'ushuru', au 'kutoa mzigo'.",
    "If you paid via M-PESA, call Safaricom immediately on 234 or 100 to report the transaction as fraud and request an urgent reversal.":
        "Ikiwa ulilipa kupitia M-PESA, piga simu Safaricom mara moja kwa 234 au 100 kuripoti muamala kama ulaghai na kuomba kurejeshewa kwa dharura.",
    "Save all evidence: keep your M-PESA confirmation SMS, seller phone or Till number, and chat screenshots.":
        "Hifadhi ushahidi wote: weka SMS ya uthibitisho wa M-PESA, nambari ya simu au Till ya muuzaji, na picha za skrini za mazungumzo.",
    "Report this seller on Toroka using the 'Report this' button below to alert other buyers.":
        "Ripoti muuzaji huyu kwenye Toroka kwa kutumia kitufe cha 'Ripoti hii' hapa chini ili kuwatahadharisha wanunuzi wengine.",
}
LIMITS_SW = {
    "It did not contact the sender or open live websites on your behalf.": "Haikuwasiliana na mtumaji wala kufungua tovuti hai kwa niaba yako.",
}


def localize(d: dict, lang: str) -> dict:
    """Return a copy of an assessment dict in `lang` ('en' returns it unchanged apart from label_text)."""
    out = copy.deepcopy(d)
    lang = lang if lang in LABELS else "en"
    out["language"] = lang
    has_incident = any(f.get("code") == "REPORTED_FRAUD_INCIDENT" for f in out.get("findings", []))
    if has_incident:
        out["label_text"] = "Reported Fraud Incident" if lang == "en" else "Tukio la Ulaghai Lililoripotiwa"
    else:
        out["label_text"] = LABELS[lang][d["label"]]
    if lang == "en":
        return out
    untranslated = 0
    for f in out["findings"]:
        tr = FINDINGS_SW.get(f["code"])
        if tr:
            f["plain_text"], f["why_it_matters"] = tr
        else:
            untranslated += 1
    for n in out["next_steps"]:
        if n["text"] in NEXT_STEPS_SW:
            n["text"] = NEXT_STEPS_SW[n["text"]]
        elif n["text"].startswith("Open the site by typing its address yourself, or from the organisation's official app, and check it matches exactly: "):
            hosts = n["text"].split("check it matches exactly: ", 1)[1].rstrip(".")
            n["text"] = f"Fungua tovuti kwa kuandika anwani yenyewe au kupitia programu rasmi ya shirika, kisha hakikisha inalingana kabisa: {hosts}. Nakala za tovuti halisi pia zipo."
        elif n["text"].startswith("Keep order confirmations and receipts, and contact them only through the details listed on their official site."):
            n["text"] = "Hifadhi uthibitisho wa oda na risiti, na wasiliana nao kupitia maelezo yaliyo kwenye tovuti yao rasmi pekee."
        else:
            untranslated += 1
    out["limitations"] = [LIMITS_SW.get(x, x) for x in out["limitations"]]
    if has_incident:
        out["summary"] = "Tukio Lililoripotiwa. Umeripoti kutuma pesa kwa muuzaji bila kupokea mzigo, au kulaghaiwa. Chukua hatua za dharura kujaribu kurudisha malipo na kuripoti muuzaji huyu."
    else:
        first = out["findings"][0]["plain_text"] if out["findings"] else ""
        if d["label"] == "high_risk" and out["findings"] and out["findings"][0]["code"] not in FINDINGS_SW:
            first = d["findings"][0]["plain_text"]
        out["summary"] = SUMMARY_SW[d["label"]].format(lead=first).replace("  ", " ").strip()
    out["translation_status"] = "draft_needs_native_review" + ("; some text is still in English" if untranslated else "")
    return out
