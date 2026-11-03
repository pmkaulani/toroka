"""Toroka Scam Encyclopedia & Unified Threat Taxonomy (Blueprint v5.0).

Provides a comprehensive, maintainable scam classification system covering:
1. Mobile money, M-Pesa, banking and payment scams
2. Online shopping, social commerce & marketplace scams
3. Job recruitment, online income and task scams
4. Investment, crypto, forex, Ponzi and pyramid schemes
5. Government, police, financial institution, telecom, employer and platform impersonation
6. Romance, confidence, emotional manipulation and extortion
7. Phishing, QR-code phishing, account takeover and malicious technology
8. AI-generated impersonation, synthetic media and fake tools
9. Property, rental, vehicle, travel, accommodation and service fraud
10. Business email compromise, fake invoices and supplier fraud
11. Prizes, free money, giveaways, grants and advance-fee schemes
12. Emerging and specialized scam patterns

Includes 10 core investigation workflows, evidence provenance tracking,
exact-identity correlation across channels, and multi-category labeling.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .normalize import mask_phone
from .vocabulary import Label


class ScamDomain(StrEnum):
    MOBILE_MONEY = "mobile_money_and_payments"
    ONLINE_SHOPPING = "online_shopping_and_social_commerce"
    EMPLOYMENT = "employment_and_income"
    INVESTMENT = "investment_crypto_and_forex"
    IMPERSONATION = "impersonation_and_fake_authority"
    ROMANCE_EXTORTION = "romance_and_extortion"
    PHISHING_TECH = "phishing_and_account_takeover"
    AI_SCAMS = "ai_generated_and_synthetic_fraud"
    PROPERTY_TRAVEL = "property_travel_and_services"
    BUSINESS_FRAUD = "business_and_supplier_fraud"
    PRIZES_GRANTS = "prizes_grants_and_advance_fees"
    EMERGING = "emerging_and_specialized"


class InvestigationWorkflow(StrEnum):
    MESSAGE_CHECK = "message_check"
    SCREENSHOT_INSPECTION = "screenshot_inspection"
    SOCIAL_ACCOUNT_CHECK = "social_account_check"
    ONLINE_SHOP_INVESTIGATION = "online_shop_investigation"
    LINK_WEBSITE_CHECK = "link_website_check"
    PAYMENT_CHECK = "payment_check"
    JOB_INVESTMENT_CHECK = "job_investment_check"
    EXISTING_SCAM_LOOKUP = "existing_scam_lookup"
    POST_SCAM_HELP = "post_scam_help"
    GENERAL_QUESTION = "general_question"


class ProvenanceType(StrEnum):
    VERIFIED_FACT = "verified_fact"
    CORROBORATED_REPORT = "independently_corroborated_report"
    UNVERIFIED_ALLEGATION = "unverified_allegation"
    MODEL_INFERENCE = "model_generated_inference"
    CONFLICTING_EVIDENCE = "conflicting_evidence"


@dataclass(frozen=True)
class ScamPattern:
    id: str
    name: str
    domain: ScamDomain
    secondary_domains: list[ScamDomain] = field(default_factory=list)
    channels: list[str] = field(default_factory=lambda: ["sms", "whatsapp", "social", "web"])
    indicators: list[str] = field(default_factory=list)
    risk_level: Label = Label.HIGH_RISK
    description: str = ""
    keywords: list[str] = field(default_factory=list)
    regex_pattern: str | None = None
    verification_steps_en: list[str] = field(default_factory=list)
    verification_steps_sw: list[str] = field(default_factory=list)
    action_en: list[str] = field(default_factory=list)
    action_sw: list[str] = field(default_factory=list)


# --- 1. Comprehensive Pattern Registry ---
PATTERNS: dict[str, ScamPattern] = {
    # 1. Mobile Money & Payments
    "MPESA_FAKE_CONFIRMATION": ScamPattern(
        id="MPESA_FAKE_CONFIRMATION",
        name="Fake M-PESA Payment Confirmation",
        domain=ScamDomain.MOBILE_MONEY,
        secondary_domains=[ScamDomain.BUSINESS_FRAUD, ScamDomain.ONLINE_SHOPPING],
        channels=["sms", "whatsapp", "screenshot"],
        indicators=["SMS_FROM_PHONE_NUMBER", "UNVERIFIED_SCREENSHOT", "URGENT_GOODS_RELEASE"],
        risk_level=Label.HIGH_RISK,
        description="Buyer sends a forged SMS or fabricated screenshot claiming payment was sent, pressuring the seller to release goods before checking their actual M-PESA balance.",
        regex_pattern=r"(?i)(?:nimetuma\s+pesa|angalia\s+message|check\s+message\s+hapo\s+juu|confirm\s+receipt|confirmed\.\s+ksh|sent\s+to\s+.*on\s+\d{1,2}/\d{1,2}/\d{2,4}\s+at)",
        verification_steps_en=[
            "Never release goods based on a forwarded SMS or screenshot sent by the buyer.",
            "Dial *334# or open your official Safaricom M-PESA App to check your actual account balance.",
            "Confirm that the incoming SMS originates from the alphanumeric sender ID 'MPESA' and not a standard 07xx or 01xx phone number.",
        ],
        verification_steps_sw=[
            "Kamwe usitoe bidhaa kwa kutegemea picha ya screenshot au SMS iliyotumwa na mnunuzi.",
            "Piga *334# au fungua M-PESA App rasmi kuthibitisha salio lako halisi la akaunti.",
            "Hakikisha ujumbe wa uthibitisho unatoka kwa jina rasmi la 'MPESA' wala si nambari ya kawaida ya simu (07xx au 01xx).",
        ],
        action_en=["Do not dispatch goods until funds are confirmed in your M-PESA account."],
        action_sw=["Usitoe mzigo mpaka ujiridhishe kuwa pesa imeingia kwenye simu yako."],
    ),
    "MPESA_FAKE_REVERSAL": ScamPattern(
        id="MPESA_FAKE_REVERSAL",
        name="Fake Reversal & Mistaken Payment Trap",
        domain=ScamDomain.MOBILE_MONEY,
        secondary_domains=[ScamDomain.IMPERSONATION],
        channels=["sms", "phone_call", "whatsapp"],
        indicators=["PRESSURE_TO_REFUND", "NO_MATCHING_BALANCE_INCREASE", "TUMA_NYUMA_PRESSURE"],
        risk_level=Label.HIGH_RISK,
        description="Scammer claims to have sent money by mistake and calls or texts demanding you immediately send it back ('tuma nyuma') before your line is allegedly blocked.",
        regex_pattern=r"(?i)(?:nimetuma\s+kwa\s+nambari\s+mbaya|nimekosea\s+nambari|tuma\s+nyuma|rudisha\s+pesa|rudisha\s+sasa|sent\s+by\s+mistake|reverse\s+transaction|reversal\s+request)",
        verification_steps_en=[
            "Do not manually send money back. Safaricom handles genuine transaction reversals centrally.",
            "Instruct the caller to forward the M-PESA confirmation SMS to 456 to trigger an official reversal.",
            "Verify your balance on *334#; scammers often forge the confirmation SMS without sending any money.",
        ],
        verification_steps_sw=[
            "Usirudishe pesa wewe mwenyewe ('tuma nyuma'). Safaricom hufanya reversal rasmi moja kwa moja.",
            "Mwambie mtumaji atume ule ujumbe wa M-PESA kwenda nambari 456 ili Safaricom washughulikie.",
            "Kagua salio lako kwa *334#; mara nyingi walaghai hutuma SMS feki bila kutuma pesa yoyote.",
        ],
        action_en=["Forward suspicious reversal messages to Safaricom via SMS 456."],
        action_sw=["Sambaza ujumbe wenye shaka kwenda Safaricom kupitia SMS 456."],
    ),
    "PIN_OTP_THEFT": ScamPattern(
        id="PIN_OTP_THEFT",
        name="PIN & OTP Credential Theft",
        domain=ScamDomain.MOBILE_MONEY,
        secondary_domains=[ScamDomain.PHISHING_TECH, ScamDomain.IMPERSONATION],
        channels=["phone_call", "sms", "whatsapp", "web"],
        indicators=["DEMAND_FOR_PIN", "DEMAND_FOR_OTP", "ACCOUNT_SUSPENSION_BLUFF"],
        risk_level=Label.HIGH_RISK,
        description="Criminals pose as customer support, fraud investigators, or verification agents asking for your 4-digit M-PESA PIN or one-time verification code.",
        regex_pattern=r"(?i)(?:(?:send|confirm|reply\s+with|enter|share|read\s+me)\s+(?:your\s+)?(?:m-?pesa\s+)?(?:pin|otp|code|password)|one-time\s+code|otp\s+code|verification\s+code|nambari\s+ya\s+siri|tuma\s+pin)",
        verification_steps_en=[
            "Safaricom, banks, and government platforms will NEVER ask for your M-PESA PIN or OTP.",
            "Never read out or type a code received via SMS into an unsolicited phone call or webpage.",
            "If your PIN was disclosed, change it immediately on *334# or call Safaricom on 100/234.",
        ],
        verification_steps_sw=[
            "Safaricom, benki na serikali HAWAWEZI KAMWE kukuomba PIN yako ya M-PESA wala nambari ya siri ya OTP.",
            "Kamwe usisomee mtu wala kuweka nambari ya uthibitisho (OTP) kwenye tovuti usiyoijua.",
            "Kama umetoa PIN, ibadilishe mara moja kwa kupiga *334# au piga huduma kwa wateja 100 au 234.",
        ],
        action_en=["Never disclose your PIN or OTP to anyone under any circumstances."],
        action_sw=["Kamwe usitoe PIN wala OTP yako kwa mtu yeyote."],
    ),
    "SIM_SWAP_TAKEOVER": ScamPattern(
        id="SIM_SWAP_TAKEOVER",
        name="SIM Swap & Line Takeover Fraud",
        domain=ScamDomain.MOBILE_MONEY,
        secondary_domains=[ScamDomain.PHISHING_TECH],
        channels=["phone_call", "sms"],
        indicators=["UNAUTHORIZED_SIM_CHANGE", "SUDDEN_LOSS_OF_SIGNAL", "IMPERSONATED_TELECOM"],
        risk_level=Label.HIGH_RISK,
        description="Fraudsters socially engineer telecom operators or victims to swap a mobile line to a criminal SIM card to hijack banking and M-PESA OTPs.",
        regex_pattern=r"(?i)(?:sim\s*swap|line\s+replacement|upgrade\s+your\s+sim|badilisha\s+laini|sim\s+card\s+registration|line\s+yafungwa)",
        verification_steps_en=[
            "If your mobile network drops unexpectedly and says 'No Service' or 'SIM Not Provisioned', contact Safaricom immediately from another phone.",
            "Register for Safaricom's free SIM Swap protection to prevent unauthorized swaps.",
        ],
        verification_steps_sw=[
            "Laini yako ikipoteza mtandao ghafla bila sababu, piga simu kwa Safaricom mara moja kupitia simu nyingine.",
            "Jiunge na huduma ya ulinzi wa SIM swap ya Safaricom kuzuia laini yako kuhamishwa bila idhini.",
        ],
        action_en=["Call 100 or 234 immediately if your phone suddenly loses cellular network access."],
        action_sw=["Piga 100 au 234 mara moja iwapo laini yako imepoteza mtandao ghafla."],
    ),
    "FAKE_LOAN_UPGRADE_FEE": ScamPattern(
        id="FAKE_LOAN_UPGRADE_FEE",
        name="Fake Instant Loan & Fuliza Limit Boost Fee",
        domain=ScamDomain.MOBILE_MONEY,
        secondary_domains=[ScamDomain.PRIZES_GRANTS],
        channels=["sms", "whatsapp", "social"],
        indicators=["UPFRONT_PROCESSING_FEE", "ALGORITHMIC_LIMIT_EXPLOIT", "UNVERIFIED_APP"],
        risk_level=Label.HIGH_RISK,
        description="Promising instant loans or artificial Fuliza limit upgrades in exchange for an upfront 'commitment fee' or 'registration deposit' sent to a personal number.",
        regex_pattern=r"(?i)(?:fuliza\s+boost|boost\s+limit|processing\s+fee\s+to\s+receive|ada\s+ya\s+usajili\s+wa\s+mkopo|instant\s+loan|mkopo\s+wa\s+haraka|pay\s+ksh\s+\d+\s+to\s+get\s+loan)",
        verification_steps_en=[
            "Fuliza and M-Shwari limits are determined strictly by Safaricom algorithms based on your usage history. No human or third-party agent can boost them.",
            "Legitimate lenders never ask for a processing fee paid via personal M-PESA before disbursing a loan.",
        ],
        verification_steps_sw=[
            "Kiwango cha Fuliza huamuliwa na mifumo ya kompyuta ya Safaricom kulingana na matumizi yako. Hakuna mtu anayeweza kuongeza limit yako kwa ada.",
            "Watoa mikopo halali hawaombi ada ya usajili kupitia M-PESA kabla ya kutoa mkopo.",
        ],
        action_en=["Never pay money upfront to receive a loan or limit increase."],
        action_sw=["Kamwe usilipe pesa mapema ili kupewa mkopo au kuongezewa limit."],
    ),

    # 2. Online Shopping & Social Commerce
    "SHOP_ADVANCE_DEPOSIT_TRAP": ScamPattern(
        id="SHOP_ADVANCE_DEPOSIT_TRAP",
        name="Social Commerce Advance Deposit & Ghost Delivery Scam",
        domain=ScamDomain.ONLINE_SHOPPING,
        secondary_domains=[ScamDomain.MOBILE_MONEY],
        channels=["instagram", "tiktok", "facebook", "whatsapp"],
        indicators=["ADVANCE_RIDER_FEE", "ONLINE_ONLY_NO_WALKINS", "DISABLED_COMMENTS", "POCHI_OR_PERSONAL_NUMBER"],
        risk_level=Label.HIGH_RISK,
        description="Online shop on Instagram/TikTok demands upfront 'delivery fee', 'rider fare', or 'commitment deposit' before dispatching goods, then blocks the buyer.",
        regex_pattern=r"(?i)(?:lipa\s+rider|delivery\s+fee\s+first|commitment\s+deposit|pesa\s+ya\s+usafirishaji|pay\s+on\s+delivery\s+not\s+allowed|dispatch\s+fee|we\s+only\s+deliver)",
        verification_steps_en=[
            "Verify the exact seller identity, the named payment recipient, written delivery/refund terms, and available buyer protection before paying.",
            "If the seller claims a physical pickup address, verify it independently; an online-only business is not automatically fraudulent.",
            "Review the account's public history, recent name changes if visible, independent complaints, and whether product images or claims appear elsewhere.",
            "Treat personal payment destinations, deposits, or restricted comments as context requiring verification, not standalone proof of fraud.",
        ],
        verification_steps_sw=[
            "Thibitisha utambulisho wa muuzaji, mpokeaji wa malipo na masharti ya usafirishaji/kurejesha bidhaa kabla ya kulipa.",
            "Ikiwa muuzaji ametoa anwani ya kuchukulia bidhaa, ithibitishe kwa njia huru; duka la mtandaoni pekee si ushahidi wa utapeli.",
            "Kagua historia ya akaunti, malalamiko huru na kama picha au madai ya bidhaa yanaonekana kwenye maduka mengine.",
            "Nambari binafsi, amana au maoni yaliyofungwa ni sababu za kuuliza na kuthibitisha zaidi, si ushahidi wa moja kwa moja wa utapeli.",
        ],
        action_en=["Verify any advance delivery request, the recipient and the seller independently before paying; a request is a warning sign only in context."],
        action_sw=["Thibitisha ombi la ada ya usafirishaji, mpokeaji na muuzaji kwa njia huru kabla ya kulipa; ombi hilo lichunguzwe kulingana na muktadha."],
    ),
    "SHOP_IMPERSONATION_CLONE": ScamPattern(
        id="SHOP_IMPERSONATION_CLONE",
        name="Counterfeit Shop & Boutique Impersonation",
        domain=ScamDomain.ONLINE_SHOPPING,
        secondary_domains=[ScamDomain.IMPERSONATION],
        channels=["instagram", "tiktok", "facebook"],
        indicators=["SLIGHT_HANDLE_VARIATION", "COPIED_PHOTOS", "PRICE_TOO_GOOD_TO_BE_TRUE"],
        risk_level=Label.HIGH_RISK,
        description="Fraudulent social media page clones a renowned Kenyan brand or boutique, using copied photos and logos with subtle handle differences (e.g., adding underscores or dots).",
        regex_pattern=r"(?i)(?:official_store|official_page|original_shop|discount_kenya|sale_kenya|clearance_sale_kenya)",
        verification_steps_en=[
            "Check the exact spelling of the username and compare it to the verified merchant's official website.",
            "Look for customer reviews, tagged photos, and check whether comments are restricted.",
            "Insist on paying to an official Safaricom Buy Goods Till registered in the legitimate business name.",
        ],
        verification_steps_sw=[
            "Chunguza tahajia kamili ya jina la akaunti na ulinganishe na tovuti rasmi ya biashara hiyo.",
            "Tazama picha zilizowekwa tag na wateja wengine, na uhakikishe sehemu ya maoni haijafungwa.",
            "Sisitiza kulipa kwenye Buy Goods Till rasmi ya Safaricom iliyo na jina kamili la biashara.",
        ],
        action_en=["Verify the official handle on the company's verified website before making any purchase."],
        action_sw=["Thibitisha ukurasa rasmi kwenye tovuti ya kampuni kabla ya kununua."],
    ),
    "SHOP_BUYER_OVERPAYMENT": ScamPattern(
        id="SHOP_BUYER_OVERPAYMENT",
        name="Marketplace Buyer Fake Payment & Overpayment Trap",
        domain=ScamDomain.ONLINE_SHOPPING,
        secondary_domains=[ScamDomain.BUSINESS_FRAUD],
        channels=["whatsapp", "sms", "jiji", "marketplace"],
        indicators=["OVERPAYMENT_CLAIM", "FORGED_RECEIPT", "URGENT_CASH_REFUND_DEMAND"],
        risk_level=Label.HIGH_RISK,
        description="Buyer targeting online sellers sends an altered payment screenshot claiming they 'accidentally overpaid' and pressures the seller to refund the difference via M-PESA.",
        regex_pattern=r"(?i)(?:nimetuma\s+zaidi|nimekosea\s+nimetuma\s+extra|overpaid|refund\s+the\s+difference|send\s+back\s+the\s+extra)",
        verification_steps_en=[
            "Never issue a refund without verifying that the funds cleared into your actual bank or M-PESA statement.",
            "Do not trust SMS forwarded by the buyer or screenshots of payment portals.",
        ],
        verification_steps_sw=[
            "Kamwe usirudishe pesa bila kuthibitisha kuwa fedha zimeingia rasmi kwenye M-PESA au akaunti yako ya benki.",
            "Usiamini SMS wala picha ya screenshot iliyotumwa na mnunuzi.",
        ],
        action_en=["Check your actual M-PESA balance on *334# before entertaining any refund requests."],
        action_sw=["Kagua salio lako halisi kwa kupiga *334# kabla ya kurudisha pesa yoyote."],
    ),

    # 3. Employment & Task Scams
    "JOB_RECRUITMENT_FEE": ScamPattern(
        id="JOB_RECRUITMENT_FEE",
        name="Fake Job Recruitment & Medical/Badge Fee Trap",
        domain=ScamDomain.EMPLOYMENT,
        secondary_domains=[ScamDomain.IMPERSONATION],
        channels=["whatsapp", "sms", "facebook", "telegram", "email"],
        indicators=["UPFRONT_APPLICATION_FEE", "MEDICAL_EXAM_FEE", "PERSONAL_MPESA_FOR_EMPLOYMENT"],
        risk_level=Label.HIGH_RISK,
        description="Scammers advertise fake job vacancies at major organizations (UN, KRA, supermarkets, hospitals) and demand 'interview fees', 'uniform deposits', or 'medical clearance fees'.",
        regex_pattern=r"(?i)(?:interview\s+fee|medical\s+fee|uniform\s+fee|badge\s+fee|appointment\s+letter.*fee|registration\s+fee.*job|kulipia\s+fomu|ada\s+ya\s+usaili|shortlisted.*pay)",
        verification_steps_en=[
            "Legitimate Kenyan employers NEVER charge job application fees, interview fees, or uniform deposits via personal M-PESA.",
            "Official recruitment is managed through corporate career portals or National Employment Authority (nea.go.ke).",
            "Any job offer demanding payment to an individual 07xx/01xx phone number is 100% fraudulent.",
        ],
        verification_steps_sw=[
            "Waajiri halali wa Kenya HAWATOZI ada za usaili, sare za kazi, wala vipimo vya afya kupitia M-PESA.",
            "Kazi halali hutangazwa kwenye tovuti rasmi za mashirika au tovuti ya serikali ya NEA (nea.go.ke).",
            "Tangazo lolote la kazi linalodai pesa kupitia nambari ya kibinafsi ni utapeli kwa asilimia 100.",
        ],
        action_en=["Walk away immediately. Genuine jobs do not charge candidates to be interviewed or hired."],
        action_sw=["Ondoka mara moja. Kazi halali hazitozi pesa ili ufanyiwe usaili au kuajiriwa."],
    ),
    "JOB_TASK_BOOSTING_SCAM": ScamPattern(
        id="JOB_TASK_BOOSTING_SCAM",
        name="Task & Video-Liking Booster Scam",
        domain=ScamDomain.EMPLOYMENT,
        secondary_domains=[ScamDomain.INVESTMENT],
        channels=["telegram", "whatsapp", "tiktok"],
        indicators=["INITIAL_SMALL_PAYOUT", "VIP_DEPOSIT_TRAP", "FICTIONAL_DASHBOARD_BALANCE"],
        risk_level=Label.HIGH_RISK,
        description="Victims are paid KSh 200-500 to like YouTube or TikTok videos to build trust, then lured into depositing KSh 3,000-50,000 for 'VIP tasks' before withdrawals are frozen.",
        regex_pattern=r"(?i)(?:like\s+youtube\s+videos|like\s+tiktok|earn\s+ksh\s+\d+.*per\s+day|vip\s+task|deposit\s+to\s+unlock\s+withdrawal|pata\s+pesa\s+kwa\s+kulike|recharge\s+to\s+withdraw)",
        verification_steps_en=[
            "Golden Rule: Never pay money to earn money. Paying to unlock a job balance is the definitive signature of a task Ponzi scheme.",
            "Initial small payments (KSh 200-500) are psychological bait funded by previous victims' deposits.",
            "Once you deposit larger sums, the Telegram admin will demand 'tax' or 'recharge fees' and will never release your funds.",
        ],
        verification_steps_sw=[
            "Kanuni Kuu: Kamwe usilipe pesa ili upate pesa. Kudaiwa pesa ili ufungue kazi ni mtego mkuu wa utapeli wa mitandaoni.",
            "Malipo madogo ya kwanza (KSh 200-500) ni chambo cha kukuingiza mtegoni ili uwaamini.",
            "Ukituma pesa kubwa, msimamizi wa kundi la Telegram atadai 'kodi' na hatakurudishia chochote.",
        ],
        action_en=["Stop sending money and leave the Telegram group immediately. Your deposits cannot be recovered."],
        action_sw=["Acha kutuma pesa na utoke kwenye kundi la Telegram mara moja. Fedha hizo hazitarudishwa."],
    ),

    # 4. Investment, Crypto & Forex
    "INVEST_PONZI_CRYPTO_FOREX": ScamPattern(
        id="INVEST_PONZI_CRYPTO_FOREX",
        name="Crypto, Forex & High-Yield Ponzi Scheme",
        domain=ScamDomain.INVESTMENT,
        secondary_domains=[ScamDomain.MOBILE_MONEY],
        channels=["whatsapp", "telegram", "facebook", "tiktok"],
        indicators=["GUARANTEED_DAILY_RETURNS", "UNREGULATED_PLATFORM", "WITHDRAWAL_TAX_DEMAND"],
        risk_level=Label.HIGH_RISK,
        description="Unregulated schemes promising 20%-100% daily or weekly returns on cryptocurrency or forex trading. Real trading carries substantial risk and never guarantees fixed returns.",
        regex_pattern=r"(?i)(?:guarantee(?:d)?.*(?:returns?|profits?)|(?:earn|get|make)\s+\d+%.*daily|crypto\s+(?:investment|trading|pool)|forex\s+(?:mentor|trading)|(?:binance|bitcoin|crypto)\s+arbitrage|faida\s+ya\s+uhakika|invest\s+\d+.*earn|cma\s+license)",
        verification_steps_en=[
            "The Capital Markets Authority (CMA) cautions that any platform promising guaranteed fixed returns without an official CMA license is an illegal Ponzi scheme.",
            "Check the CMA list of licensed market intermediaries at cma.or.ke before investing.",
            "If a platform demands extra fees or taxes to release your profits, it is a withdrawal extortion scam.",
        ],
        verification_steps_sw=[
            "Mamlaka ya Masoko ya Mitaji (CMA) inaonya kuwa jukwaa lolote linaloahidi faida kubwa ya uhakika bila leseni ya CMA ni utapeli.",
            "Kagua orodha ya makampuni yenye leseni kwenye tovuti ya cma.or.ke kabla ya kuwekeza.",
            "Jukwaa likidai ada ya ziada au 'kodi' ili utoe faida yako, huo ni utapeli wa kuzuia pesa.",
        ],
        action_en=["Never invest funds in unregulated platforms promising guaranteed fixed returns."],
        action_sw=["Kamwe usiwekeze pesa kwenye makampuni yasiyo na leseni ya CMA yanayoahidi faida ya uhakika."],
    ),

    # 5. Impersonation & Fake Authority
    "GOV_AUTHORITY_IMPERSONATION": ScamPattern(
        id="GOV_AUTHORITY_IMPERSONATION",
        name="Government & eCitizen/KRA Impersonation",
        domain=ScamDomain.IMPERSONATION,
        secondary_domains=[ScamDomain.PHISHING_TECH],
        channels=["sms", "whatsapp", "web"],
        indicators=["NON_GO_KE_DOMAIN", "PERSONAL_PAYMENT_FOR_GOV", "ARREST_OR_FINE_THREAT"],
        risk_level=Label.HIGH_RISK,
        description="Fake SMS or cloned portals impersonating eCitizen, KRA, or NTSA demanding immediate payment or linking to phishing domains (.xyz, .top, .site).",
        regex_pattern=r"(?i)(?:ecitizen(?!\.go\.ke)|kra(?!\.go\.ke)|ntsa(?!\.go\.ke)|national\s+police|dci\s+summons|kplc\s+token.*bonus|huduma\s+centre.*fee)",
        verification_steps_en=[
            "Official Kenya government portals strictly use '.go.ke' domains (e.g. ecitizen.go.ke, kra.go.ke). Never trust .com, .org, or .xyz links.",
            "Legitimate eCitizen payments are processed EXCLUSIVELY through the official Government Paybill 222222 with an invoice reference number.",
            "The government never conducts enforcement or demands fines via personal phone numbers or WhatsApp.",
        ],
        verification_steps_sw=[
            "Tovuti zote halali za serikali ya Kenya huishia na '.go.ke' (kama ecitizen.go.ke au kra.go.ke). Kamwe usiamini tovuti za .xyz au .com.",
            "Malipo yote halali ya eCitizen hufanywa KIPEKEE kupitia Paybill ya serikali 222222 kwa nambari ya ankara (invoice number).",
            "Serikali haidai faini wala kutoa notisi za kukamatwa kupitia WhatsApp au nambari binafsi.",
        ],
        action_en=["Access government services only by typing 'ecitizen.go.ke' directly into your browser."],
        action_sw=["Fikia huduma za serikali kwa kuandika moja kwa moja 'ecitizen.go.ke' kwenye kivinjari chako."],
    ),

    # 6. Romance, Extortion & Confidence Scams
    "ROMANCE_PARCEL_CUSTOMS": ScamPattern(
        id="ROMANCE_PARCEL_CUSTOMS",
        name="Romance & Fake JKIA Customs Parcel Extortion",
        domain=ScamDomain.ROMANCE_EXTORTION,
        secondary_domains=[ScamDomain.IMPERSONATION, ScamDomain.MOBILE_MONEY],
        channels=["whatsapp", "facebook", "instagram", "phone_call"],
        indicators=["OVERSEAS_GIFT_CLAIM", "JKIA_CLEARANCE_FEE", "PERSONAL_MPESA_CUSTOMS"],
        risk_level=Label.HIGH_RISK,
        description="An online romantic interest claims to have sent luxury gifts/money from abroad. A fake 'JKIA customs agent' or courier then calls demanding thousands in clearance fees.",
        # This specialised pattern requires BOTH a parcel/gift story AND an explicit
        # request to pay a release/customs fee. Generic mentions of customs or clearance
        # are common in legitimate shipping and must not alone be labeled as a scam.
        regex_pattern=(r"(?is)\A(?=.*(?:diplomatic\s+parcel|parcel\s+at\s+jkia|gift\s+box|"
                       r"(?:lover|partner|doctor\s+abroad).{0,100}(?:sent|sending).{0,40}(?:gift|parcel|box)|"
                       r"mizigo\s+ya\s+jkia))"
                       r"(?=.*(?:(?:pay|send|transfer|lipa|tuma|demand|asking\s+for|asks?\s+for).{0,100}"
                       r"(?:clearance|customs|release|processing)?\s*(?:fee|tax|charge|payment)|"
                       r"(?:fee|tax|charge|payment).{0,100}(?:pay|send|transfer|lipa|tuma|demand|asking\s+for|asks?\s+for)))"),
        verification_steps_en=[
            "Verify any parcel and fee directly with the named courier or customs authority using contact details you find independently.",
            "A story about an overseas gift plus a demanded personal payment to release it is a significant warning pattern; context and evidence still matter.",
            "Do not send money to an unfamiliar recipient until the shipment, fee and recipient are independently verified.",
        ],
        verification_steps_sw=[
            "Thibitisha mzigo na ada moja kwa moja kwa kampuni ya usafirishaji au mamlaka ya forodha kupitia mawasiliano uliyoyapata kwa njia huru.",
            "Hadithi ya zawadi kutoka nje pamoja na ombi la malipo binafsi ili kuachilia mzigo ni ishara muhimu ya tahadhari; muktadha na ushahidi bado ni muhimu.",
            "Usitume pesa kwa mpokeaji usiyemfahamu kabla ya kuthibitisha mzigo, ada na mpokeaji kwa njia huru.",
        ],
        action_en=["Pause payment and independently verify the shipment, the fee and the payment recipient."],
        action_sw=["Sitisha malipo na uthibitishe mzigo, ada na mpokeaji wa malipo kupitia njia huru."],
    ),
    "SEXTORTION_BLACKMAIL": ScamPattern(
        id="SEXTORTION_BLACKMAIL",
        name="Sextortion & Private Media Blackmail",
        domain=ScamDomain.ROMANCE_EXTORTION,
        secondary_domains=[ScamDomain.PHISHING_TECH],
        channels=["whatsapp", "instagram", "telegram", "facebook"],
        indicators=["INTIMATE_MEDIA_COERCION", "SHORT_DEADLINE_PRESSURE", "CONTACT_LEAK_THREAT"],
        risk_level=Label.HIGH_RISK,
        description="Perpetrator lures victim into sharing intimate images/videos on video call or chat, then threatens to blast the media to friends and family unless paid via M-PESA.",
        regex_pattern=r"(?i)(?:leak.*(?:photos?|videos?|nudes?|pics?)|send\s+to.*(?:family|friends|contacts)|private\s+(?:photos?|videos?|images?|pics?)|intimate\s+(?:photos?|videos?|images?|pics?)|nude\s+photos?|sextortion|blackmail|picha\s+zangu\s+chafu|kusambaza\s+picha|tuma\s+pesa\s+la\s+sivyo)",
        verification_steps_en=[
            "Do not pay. Paying never stops extortion; it proves you are willing to pay and guarantees they will demand more money.",
            "Preserve all evidence: take full screenshots of the chat, their profile URL, and their payment phone number before blocking.",
            "Report immediately to the DCI Anti-Cybercrime Unit and Safaricom fraud line (333).",
        ],
        verification_steps_sw=[
            "Kamwe usilipe pesa. Kulipa hakuzuii kusambaza; kunawathibitishia unaogopa na wataendelea kudai pesa zaidi.",
            "Hifadhi ushahidi: piga picha (screenshots) za mazungumzo, ukurasa wao, na nambari waliyokupa kabla ya kuwazuia.",
            "Ripoti mara moja kwa kitengo cha DCI Cybercrime na nambari ya utapeli ya Safaricom (333).",
        ],
        action_en=["Do not pay. Block the blackmailer, preserve chat screenshots, and report to DCI Cybercrime."],
        action_sw=["Usilipe chochote. Mzuie (block), hifadhi picha za meseji, na uripoti kwa DCI Cybercrime."],
    ),

    # 7. Phishing, Account Takeover & Tech Scams
    "SMISHING_PHISHING_LINK": ScamPattern(
        id="SMISHING_PHISHING_LINK",
        name="Smishing & Fake Account Login Phishing",
        domain=ScamDomain.PHISHING_TECH,
        secondary_domains=[ScamDomain.IMPERSONATION],
        channels=["sms", "whatsapp", "email", "web"],
        indicators=["SHORTENED_OR_CLONE_URL", "ACCOUNT_SUSPENSION_URGENCY", "CREDENTIAL_HARVESTER"],
        risk_level=Label.HIGH_RISK,
        description="Deceptive text message containing a phishing link to steal passwords, credentials, or M-PESA details under the guise of parcel delivery or account issues.",
        regex_pattern=r"(?i)(?:click\s+here\s+to\s+claim|account\s+suspended.*click|update\s+your\s+details\s+via|claim\s+your\s+reward\s+at|login\s+to\s+verify.*http)",
        verification_steps_en=[
            "Never click on unsolicited links received via SMS, especially those using cheap domain extensions (.xyz, .top, .site, .vip).",
            "Always inspect the destination domain: genuine corporate websites use verified .co.ke or .com addresses.",
        ],
        verification_steps_sw=[
            "Kamwe usibonyeze viungo (links) vinavyotumwa kwa SMS, hasa vinavyoishia na .xyz, .top, au .site.",
            "Chunguza anwani ya tovuti kwa makini; mashirika halali hutumia anwani zilizothibitishwa kama .co.ke au .com.",
        ],
        action_en=["Do not click the link or enter any login credentials."],
        action_sw=["Usibonyeze kiungo wala kuweka nenosiri lako."],
    ),
    "QUISHING_QR_CODE_PHISHING": ScamPattern(
        id="QUISHING_QR_CODE_PHISHING",
        name="QR Code Phishing (Quishing)",
        domain=ScamDomain.PHISHING_TECH,
        secondary_domains=[ScamDomain.MOBILE_MONEY],
        channels=["screenshot", "in_person", "social"],
        indicators=["OBSCURED_DESTINATION_QR", "UNVERIFIED_QR_POSTER", "CREDENTIAL_PROMPT"],
        risk_level=Label.HIGH_RISK,
        description="Malicious QR codes on stickers, posters, or messages directing victims to counterfeit payment gateways or credential harvesting pages.",
        regex_pattern=r"(?i)(?:scan\s+this\s+qr|scan\s+to\s+pay|qr\s+code\s+payment|quishing)",
        verification_steps_en=[
            "Always inspect the decoded URL in your camera app before confirming navigation.",
            "Verify that the displayed business name on the payment screen matches the physical store.",
        ],
        verification_steps_sw=[
            "Kagua anwani inayotokea unapopiga picha ya QR kabla ya kuifungua.",
            "Hakikisha jina la biashara linalotokea kwenye skrini linalingana na duka unalofanya malipo.",
        ],
        action_en=["Carefully inspect the decoded link before opening any QR code destination."],
        action_sw=["Kagua kiungo kwa makini kabla ya kufungua tovuti ya QR code."],
    ),

    # 8. AI-Generated & Synthetic Scams
    "AI_VOICE_CLONING_EMERGENCY": ScamPattern(
        id="AI_VOICE_CLONING_EMERGENCY",
        name="AI Voice Cloning & Deepfake Emergency Scam",
        domain=ScamDomain.AI_SCAMS,
        secondary_domains=[ScamDomain.ROMANCE_EXTORTION, ScamDomain.IMPERSONATION],
        channels=["phone_call", "whatsapp_audio"],
        indicators=["SYNTHETIC_VOICE", "PANIC_EMERGENCY_DEMAND", "OFF_CHANNEL_PAYMENT"],
        risk_level=Label.HIGH_RISK,
        description="Using AI voice synthesis to clone a relative's voice claiming they have been arrested or involved in an accident, demanding immediate bail or hospital fees.",
        regex_pattern=r"(?i)(?:nimeshikwa\s+na\s+polisi|nimepata\s+ajali|hospital\s+bill\s+urgent|bail\s+money|send\s+to\s+this\s+number\s+my\s+phone\s+is\s+off)",
        verification_steps_en=[
            "Hang up and call your relative directly on their known, regular phone number.",
            "Establish a private family safe-word that only real family members know to defeat voice cloning.",
            "Never send emergency funds to a random stranger claiming to be a doctor or police officer without independent confirmation.",
        ],
        verification_steps_sw=[
            "Kata simu na umpigiye jamaa yako moja kwa moja kwenye nambari yake ya kawaida ya simu unayoijua.",
            "Weka nenosiri la siri la kifamilia ambalo mnalijua ninyi pekee ili kutambua kama sauti ni ya kweli.",
            "Kamwe usitume pesa kwa mtu asiyejulikana anayedai kuwa daktari au polisi bila uthibitisho huru.",
        ],
        action_en=["Call the relative back directly on their normal number before sending any money."],
        action_sw=["Mpigiye jamaa yako kwa namba yake ya kawaida kuthibitisha kabla ya kutuma pesa."],
    ),

    # 9. Property, Travel & Services
    "PROPERTY_RENTAL_VIEWING_FEE": ScamPattern(
        id="PROPERTY_RENTAL_VIEWING_FEE",
        name="House Rental & Bedsitter Viewing Fee Trap",
        domain=ScamDomain.PROPERTY_TRAVEL,
        secondary_domains=[ScamDomain.MOBILE_MONEY],
        channels=["facebook", "whatsapp", "jiji"],
        indicators=["UPFRONT_VIEWING_FEE", "STOLEN_APARTMENT_PHOTOS", "CARETAKER_IMPERSONATION"],
        risk_level=Label.HIGH_RISK,
        description="Fake landlords or agents posting luxurious bedsitters or apartments in Nairobi (Kilimani, Westlands, Roysambu) demanding KSh 500-2,000 'viewing fee' before showing the house.",
        regex_pattern=r"(?i)(?:viewing\s+fee|booking\s+fee.*house|tuma\s+pesa\s+ya\s+kuona\s+nyumba|fuel\s+ya\s+caretaker|apartment\s+for\s+rent.*deposit\s+first)",
        verification_steps_en=[
            "Viewing fees are 100% fraudulent in Kenya. Genuine caretakers and property managers show houses for free.",
            "Never send booking money before meeting the caretaker at the actual building and inspecting the premises.",
        ],
        verification_steps_sw=[
            "Ada ya kuona nyumba (viewing fee) ni utapeli nchini Kenya. Ma-caretaker halali huonyesha nyumba bila malipo.",
            "Kamwe usitume pesa ya booking kabla ya kukutana na msimamizi katika jengo husika na kuona nyumba.",
        ],
        action_en=["Never pay a viewing fee to see a rental house."],
        action_sw=["Kamwe usilipe ada ya kuona nyumba kabla ya kuingia ndani."],
    ),
    "LAND_TITLE_DEED_FRAUD": ScamPattern(
        id="LAND_TITLE_DEED_FRAUD",
        name="Land & Plot Title Deed Scam",
        domain=ScamDomain.PROPERTY_TRAVEL,
        secondary_domains=[ScamDomain.IMPERSONATION],
        channels=["in_person", "social", "phone_call"],
        indicators=["BYPASS_ARDHISASA", "MULTIPLE_ALLOCATION", "UNVERIFIED_SURVEYOR"],
        risk_level=Label.HIGH_RISK,
        description="Selling land using forged title deeds or selling the same plot to multiple buyers in satellite towns (Juja, Kitengela, Malaa, Kangundo Road).",
        regex_pattern=r"(?i)(?:plot\s+for\s+sale|title\s+deed|ardhisasa|land\s+buying|kiwanja\s+kinauzwa|beacon\s+search)",
        verification_steps_en=[
            "Conduct an official official land search on the Ministry of Lands portal: ArdhiSasa (ardhisasa.lands.go.ke).",
            "Engage a licensed surveyor from the Land Surveyors Board to confirm beacons and boundaries on ground.",
            "All payments must flow through a licensed advocate's client escrow account, NEVER directly to the seller via personal M-PESA.",
        ],
        verification_steps_sw=[
            "Fanya ukaguzi rasmi wa ardhi kupitia mfumo wa ArdhiSasa wa Wizara ya Ardhi (ardhisasa.lands.go.ke).",
            "Mtumie mpimaji ardhi mwenye leseni kuthibitisha mipaka na alama (beacons) ardhini.",
            "Malipo yote lazima yafanywe kupitia akaunti ya wakili ya escrow, WALA SI kwa M-PESA ya kibinafsi.",
        ],
        action_en=["Conduct mandatory official search on ArdhiSasa before paying for any land."],
        action_sw=["Fanya ukaguzi wa ArdhiSasa kabla ya kufanya malipo ya kiwanja."],
    ),

    # 10. Business & Supplier Fraud
    "BUSINESS_INVOICE_DIVERSION": ScamPattern(
        id="BUSINESS_INVOICE_DIVERSION",
        name="Supplier Payment Diversion & Forged Invoices",
        domain=ScamDomain.BUSINESS_FRAUD,
        secondary_domains=[ScamDomain.IMPERSONATION],
        channels=["email", "whatsapp"],
        indicators=["CHANGED_BANK_DETAILS", "TEMPLATE_WATERMARK", "UNAUTHORIZED_SUPPLIER_EMAIL"],
        risk_level=Label.HIGH_RISK,
        description="Scammers intercept supplier emails or send fake invoices claiming the supplier's bank account has changed, diverting large payments to criminal accounts.",
        regex_pattern=r"(?i)(?:updated\s+bank\s+details|change\s+of\s+bank\s+account|pay\s+to\s+new\s+account|divert\s+payment|invoicebase|template\s+invoice)",
        verification_steps_en=[
            "Perform out-of-band verification: Call the supplier using a verified phone number you already have on file, not the phone number printed on the new invoice.",
            "Verify corporate registration and match bank details against previous verified supplier remittances.",
        ],
        verification_steps_sw=[
            "Thibitisha kwa njia tofauti: Mpigiye msambazaji simu kupitia nambari uliyonayo kwenye kumbukumbu zako, wala si ile iliyoandikwa kwenye ankara mpya.",
            "Linganisha maelezo ya benki na malipo ya awali kabla ya kubadilisha akaunti ya kutuma pesa.",
        ],
        action_en=["Call the supplier directly via your verified phone records before changing payment accounts."],
        action_sw=["Wasiliana na msambazaji kwa nambari yake ya kawaida kabla ya kubadilisha akaunti."],
    ),

    # 11. Prizes, Giveaways & Advance-Fee Schemes
    "PRIZE_GIVEAWAY_ADVANCE_FEE": ScamPattern(
        id="PRIZE_GIVEAWAY_ADVANCE_FEE",
        name="Fake Lottery, Prize & Giveaway Advance Fee",
        domain=ScamDomain.PRIZES_GRANTS,
        secondary_domains=[ScamDomain.MOBILE_MONEY],
        channels=["sms", "whatsapp", "social"],
        indicators=["UNEXPECTED_LOTTERY_WIN", "DISBURSEMENT_FEE", "BONGA_POINTS_TRAP"],
        risk_level=Label.HIGH_RISK,
        description="Messages announcing you have won KSh 50,000-500,000 or a luxury smartphone, but demanding an upfront 'processing fee', 'delivery charge', or OTP to release the prize.",
        regex_pattern=r"(?i)(?:congratulations.*you\s+won|hongera\s+umeshinda|processing\s+fee\s+to\s+claim|bonga\s+points.*expiring|shinda\s+na\s+safaricom|claim\s+your\s+prize)",
        verification_steps_en=[
            "You cannot win a promotion or lottery that you never entered.",
            "Legitimate corporate promotions (like Safaricom promotions) NEVER ask winners to pay release or courier fees to claim a prize.",
            "Safaricom only contacts promotion winners via the official number 0722 000 000.",
        ],
        verification_steps_sw=[
            "Huwezi kushinda shindano ambalo hukuingia wala kushiriki.",
            "Mashindano halali ya kampuni kama Safaricom HAWADAI mshindi kulipa ada ya kutoa au kusafirisha zawadi.",
            "Safaricom huwapigia washindi KIPEKEE kupitia nambari rasmi: 0722 000 000.",
        ],
        action_en=["Never pay a fee to collect a prize. Safaricom calls winners only from 0722 000 000."],
        action_sw=["Kamwe usilipe pesa ili kupewa zawadi. Safaricom hupiga simu kutoka 0722 000 000 pekee."],
    ),

    # 12. Emerging & Recovery Scams
    "SCAM_RECOVERY_FEE_FRAUD": ScamPattern(
        id="SCAM_RECOVERY_FEE_FRAUD",
        name="Fake Fund Recovery & Secondary Exploitation Trap",
        domain=ScamDomain.EMERGING,
        secondary_domains=[ScamDomain.IMPERSONATION],
        channels=["social", "whatsapp", "telegram", "web"],
        indicators=["UPFRONT_RECOVERY_FEE", "HACKER_ETHICAL_AGENT", "WALLET_KEY_DEMAND"],
        risk_level=Label.HIGH_RISK,
        description="Impersonators targeting previously defrauded victims promising to 'hack back' stolen crypto or recover scammed M-PESA funds in exchange for an upfront retainment fee.",
        regex_pattern=r"(?i)(?:fund\s+recovery|recover\s+lost\s+money|hacked\s+account\s+recovery|funds\s+recovered|recovery\s+agent|reversal\s+specialist|ethical\s+hacker)",
        verification_steps_en=[
            "No private third party or 'ethical hacker' can reverse an M-PESA transaction or hack a blockchain wallet.",
            "Fund recovery services demanding upfront fees are secondary scams specifically designed to exploit previous victims.",
            "Official reporting channels are Safaricom (333/100/234) and the National Police / DCI Cybercrime Unit.",
        ],
        verification_steps_sw=[
            "Hakuna mtu binafsi au 'hacker' anayeweza kurejesha pesa za M-PESA au kuingilia mifumo ya benki.",
            "Watu wanaodai kurudisha pesa zilizopotea kwa ada ni matapeli wanaowatega watu waliotapeliwa awali.",
            "Njia pekee halali ni kuripoti Safaricom (333/100/234) au kitengo cha DCI Cybercrime.",
        ],
        action_en=["Do not pay recovery fees. Report the incident through official law enforcement channels."],
        action_sw=["Usilipe ada ya kurudishiwa pesa. Ripoti kwa mamlaka rasmi za sheria."],
    ),
}


# --- 2. Classification Result Data Model ---
@dataclass
class TaxonomyClassification:
    primary_domain: ScamDomain
    secondary_domains: list[ScamDomain]
    matched_patterns: list[ScamPattern]
    indicators_detected: list[str]
    suggested_workflow: InvestigationWorkflow
    confidence: str  # strong | supporting | weak
    provenance: ProvenanceType
    risk_band: Label
    action_en: list[str]
    action_sw: list[str]
    entity_correlations: list[dict[str, str]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "primary_domain": self.primary_domain.value,
            "secondary_domains": [d.value for d in self.secondary_domains],
            "matched_patterns": [p.id for p in self.matched_patterns],
            "pattern_names": [p.name for p in self.matched_patterns],
            "indicators": self.indicators_detected,
            "workflow": self.suggested_workflow.value,
            "confidence": self.confidence,
            "provenance": self.provenance.value,
            "risk_band": self.risk_band.value,
            "action_en": self.action_en,
            "action_sw": self.action_sw,
            "entity_correlations": self.entity_correlations,
        }


# --- 3. Unified Classification Engine ---
def classify_text_threat(
    text: str,
    *,
    urls: list[Any] | None = None,
    phones: list[Any] | None = None,
    payment_ids: list[Any] | None = None,
    shop_profile: Any | None = None,
    has_images: bool = False,
    is_verified_source: bool = False,
    corroborated_reports_count: int = 0,
) -> TaxonomyClassification:
    """Classifies raw evidence against the complete Toroka Scam Encyclopedia."""
    clean = text or ""
    urls = urls or []
    phones = phones or []
    payment_ids = payment_ids or []

    matched: list[ScamPattern] = []
    indicators: list[str] = []

    # Match patterns against regex and text rules
    for pat in PATTERNS.values():
        if pat.regex_pattern and re.search(pat.regex_pattern, clean):
            matched.append(pat)
            indicators.extend(pat.indicators)

    # A shop identity is not itself a scam signal. Only match SHOP_ADVANCE_DEPOSIT_TRAP
    # when the message contains the pattern's actual behavioural indicators above.
    # Presence of a handle is descriptive context, not evidence of fraudulent conduct.
    if shop_profile and getattr(shop_profile, "handle", None):
        indicators.append("SOCIAL_SHOP_PROFILE_IDENTIFIED")

    # Check images
    if has_images:
        indicators.append("VISUAL_FORENSIC_EVIDENCE_ATTACHED")

    has_urls = bool(urls or re.search(r"https?://|www\.", clean))

    # Workflow selection
    if has_images:
        workflow = InvestigationWorkflow.SCREENSHOT_INSPECTION
    elif any(p.domain == ScamDomain.PHISHING_TECH for p in matched) or (has_urls and not any(p.domain == ScamDomain.ONLINE_SHOPPING for p in matched)):
        workflow = InvestigationWorkflow.LINK_WEBSITE_CHECK
    elif shop_profile or any(p.domain == ScamDomain.ONLINE_SHOPPING for p in matched):
        workflow = InvestigationWorkflow.ONLINE_SHOP_INVESTIGATION
    elif any(p.domain == ScamDomain.EMPLOYMENT for p in matched):
        workflow = InvestigationWorkflow.JOB_INVESTMENT_CHECK
    elif any(p.domain == ScamDomain.INVESTMENT for p in matched):
        workflow = InvestigationWorkflow.JOB_INVESTMENT_CHECK
    elif any(p.domain == ScamDomain.MOBILE_MONEY for p in matched):
        workflow = InvestigationWorkflow.PAYMENT_CHECK
    elif any(p.id == "SCAM_RECOVERY_FEE_FRAUD" for p in matched):
        workflow = InvestigationWorkflow.MESSAGE_CHECK
    elif any(q in clean.lower() for q in ["how to reverse", "i was scammed and", "nimetapeliwa nitumie"]):
        workflow = InvestigationWorkflow.POST_SCAM_HELP
    elif len(clean.strip()) > 10:
        workflow = InvestigationWorkflow.MESSAGE_CHECK
    else:
        workflow = InvestigationWorkflow.GENERAL_QUESTION

    # Primary and secondary domain resolution
    if matched:
        primary = matched[0].domain
        secondaries = list({s for p in matched for s in p.secondary_domains if s != primary})
        risk = matched[0].risk_level
    else:
        # Fallback domain based on URLs, phones, or text
        if shop_profile:
            primary = ScamDomain.ONLINE_SHOPPING
            # Account identity alone is not evidence of a scam.
            risk = Label.INCONCLUSIVE
        elif urls:
            # Presence of a URL merely selects a link-check workflow. It is not a
            # risk signal unless the domain, destination, message behaviour or sources
            # provide something suspicious to assess.
            primary = ScamDomain.PHISHING_TECH
            risk = Label.INCONCLUSIVE
        elif payment_ids:
            primary = ScamDomain.MOBILE_MONEY
            risk = Label.SUSPICIOUS_VERIFY_FIRST
        else:
            primary = ScamDomain.EMERGING
            risk = Label.INCONCLUSIVE
        secondaries = []

    # Provenance attribution
    if is_verified_source:
        provenance = ProvenanceType.VERIFIED_FACT
        risk = Label.VERIFIED_OFFICIAL
    elif corroborated_reports_count >= 2:
        provenance = ProvenanceType.CORROBORATED_REPORT
        risk = Label.HIGH_RISK
    elif corroborated_reports_count == 1:
        provenance = ProvenanceType.UNVERIFIED_ALLEGATION
    elif matched:
        provenance = ProvenanceType.MODEL_INFERENCE
    else:
        provenance = ProvenanceType.UNVERIFIED_ALLEGATION

    # Cross-channel entity correlation (Exact identity linking)
    correlations: list[dict[str, str]] = []
    if phones and shop_profile and getattr(shop_profile, "handle", None):
        ph_raw = phones[0].normalized if hasattr(phones[0], "normalized") else str(phones[0])
        correlations.append({
            "type": "social_to_phone",
            "source": f"handle:{shop_profile.handle}",
            "target": f"phone:{mask_phone(ph_raw)}",
            "confidence": "exact_submission",
        })
    if payment_ids and shop_profile and getattr(shop_profile, "handle", None):
        pid = payment_ids[0]
        correlations.append({
            "type": "social_to_payment",
            "source": f"handle:{shop_profile.handle}",
            "target": f"{getattr(pid, 'kind', 'payment')}:{getattr(pid, 'normalized', str(pid))}",
            "confidence": "exact_submission",
        })
    if urls and phones:
        ph_raw = phones[0].normalized if hasattr(phones[0], "normalized") else str(phones[0])
        correlations.append({
            "type": "url_to_phone",
            "source": f"host:{urls[0].host if hasattr(urls[0], 'host') else str(urls[0])}",
            "target": f"phone:{mask_phone(ph_raw)}",
            "confidence": "exact_submission",
        })

    # Recommended Actions
    action_en: list[str] = []
    action_sw: list[str] = []
    for pat in matched[:2]:
        action_en.extend(pat.action_en)
        action_sw.extend(pat.action_sw)
    if not action_en:
        action_en.append("No specific scam pattern was established. Verify the account and payment recipient independently before making a decision.")
        action_sw.append("Hakuna muundo maalum wa ulaghai uliothibitishwa. Thibitisha akaunti na mpokeaji wa malipo kupitia chanzo huru kabla ya kuamua.")

    # Deduplicate indicators
    unique_indicators = sorted(set(indicators))

    return TaxonomyClassification(
        primary_domain=primary,
        secondary_domains=secondaries,
        matched_patterns=matched,
        indicators_detected=unique_indicators,
        suggested_workflow=workflow,
        confidence="strong" if len(matched) >= 2 or corroborated_reports_count >= 2 else "supporting" if matched else "weak",
        provenance=provenance,
        risk_band=risk,
        action_en=action_en,
        action_sw=action_sw,
        entity_correlations=correlations,
    )
