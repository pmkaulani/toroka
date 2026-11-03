from __future__ import annotations
import re, unicodedata
from .models import LanguageAnalysis, LanguageSignal

PATTERNS = [
    ("credential.pin_request","credential_theft","high","en",["send your mpesa pin","send your m-pesa pin","share your mpesa pin","share your m-pesa pin","tell me your mpesa pin","tell me your m-pesa pin","send your otp","share the otp","give me the verification code"]),
    ("credential.pin_request.sw","credential_theft","high","sw",["tuma pin yako","nipe pin yako","nipee pin yako","nipe otp","tuma otp yako","nipe code ya mpesa","niambie pin"]),
    ("credential.pin_request.sheng","credential_theft","high","sheng",["nipee code","nipee pin","tuma code buda","toa pin yako"]),
    ("advance_fee.prize","advance_fee","high","en",["pay a small fee to release","pay processing fee to receive","activation fee to unlock","send money to claim your prize"]),
    ("advance_fee.prize.sw","advance_fee","high","sw",["lipa ada ya kutoa pesa","tuma pesa ya processing","lipa ada ya usajili kwanza","lipa kidogo utoe pesa","toa pesa ya kufungua zawadi"]),
    ("advance_fee.prize.sheng","advance_fee","high","sheng",["toa doo kwanza","tuma doo ndio utoe","weka doo ndio uingie","lipa kitu kidogo kwanza"]),
    ("job_fee.fake","job_fee","medium","en",["pay an application fee for the job","pay to secure your interview","send money for recruitment processing"]),
    ("job_fee.fake.sw","job_fee","medium","sw",["lipa ada ya kazi","tuma pesa ya interview","lipa application ya kazi","toa pesa ndio uajiriwe"]),
    ("job_fee.fake.sheng","job_fee","medium","sheng",["toa doo ya interview","lipa job fee","weka doo ndio upate kazi"]),
    ("prize.unsolicited","prize_bait","medium","en",["you have won a prize","claim your free bonus","you are our lucky winner","free betting bonus"]),
    ("prize.unsolicited.sw","prize_bait","medium","sw",["umeshinda zawadi","umebahatika kushinda","kuna pesa umeshinda","bonus ya bure"]),
    ("prize.unsolicited.sheng","prize_bait","medium","sheng",["umepata doo za bure","umeshinda kitu buda","free bonus imeingia"]),
    ("government_grant.fake","government_benefit_bait","high","en",["government grant approved pay a fee","claim your government money","your grant is ready pay to unlock"]),
    ("government_grant.fake.sw","government_benefit_bait","high","sw",["pesa za serikali zimeingia","lipa ada upate pesa za serikali","grant yako iko tayari lipa","fedha za serikali zimekubaliwa"]),
    ("government_grant.fake.sheng","government_benefit_bait","high","sheng",["dooh za serikali zimeingia","pesa ya serikali iko ready lipa","grant imeiva toa doo"]),
    ("investment.guaranteed","investment_bait","high","en",["guaranteed returns every day","double your money in seven days","risk free investment returns","guaranteed profit daily"]),
    ("investment.guaranteed.sw","investment_bait","high","sw",["ongeza pesa mara mbili","faida ya uhakika kila siku","weka pesa upate mara mbili"]),
    ("remote_access.pressure","remote_access","high","en",["install anydesk so i can help","download remote access app","share your screen so i can fix it"]),
    ("remote_access.pressure.sw","remote_access","high","sw",["install anydesk nikusaidie","fungua screen sharing","weka app ya kucontrol simu"]),
    ("urgency.payment","urgency_pressure","medium","en",["pay within ten minutes","your account will be blocked today","act now or lose the money"]),
    ("urgency.payment.sw","urgency_pressure","medium","sw",["lipa ndani ya dakika kumi","haraka kabla akaunti ifungwe","lipa sasa hivi usichelewe"]),
]

SW_TOKENS={"tuma","lipa","pesa","yako","umeshinda","serikali","kazi","haraka","ada","zawadi","nime","nipe","kidogo","sasa","weka","toa"}
SHENG_TOKENS={"buda","rada","noma","doo","msee","niaje","sai","mdosi","wasee","uko","imeiva","maze"}
NEGATIONS=["never share","do not send","don't send","dont send","do not share","don't share","dont share","avoid sharing","usitume","usiwahi tuma","usipeane","usiweke pin","hii ni scam"]


def _norm(text):
    text=unicodedata.normalize("NFKC",text).lower()
    text=re.sub(r"https?://\S+|www\.\S+"," [link] ",text)
    text=re.sub(r"[^\w\s@.+-]"," ",text)
    return re.sub(r"\s+"," ",text).strip()

def detect_language(text: str) -> tuple[str,float]:
    words=set(_norm(text).split())
    sw=len(words & SW_TOKENS); sh=len(words & SHENG_TOKENS)
    if sh>=2 and sh>=sw: return "sheng", min(.96,.55+.1*sh)
    if sw>=2: return "sw", min(.96,.55+.08*sw)
    if sh: return "sheng",.58
    if sw: return "sw",.58
    return "en",.65 if words else 0.0

def _excerpt(text, phrase):
    normalized=text
    idx=normalized.lower().find(phrase.lower())
    snippet=normalized[max(0,idx-48):idx+len(phrase)+48] if idx>=0 else phrase
    snippet=re.sub(r"\b\d{4,}\b","[number]",snippet)
    snippet=re.sub(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}","[email]",snippet,flags=re.I)
    snippet=re.sub(r"(?:\+?254|0)?7\d{8}","[phone]",snippet)
    return snippet[:180]

def analyze_message(text: str, *, max_chars: int=5000) -> LanguageAnalysis:
    if not isinstance(text,str): raise TypeError("text must be a string")
    if len(text)>max_chars: text=text[:max_chars]
    norm=_norm(text)
    language,lang_conf=detect_language(text)
    found=[]
    for pattern_id,category,severity,lang,phrases in PATTERNS:
        for phrase in phrases:
            p=_norm(phrase)
            idx=norm.find(p) if p else -1
            if idx >= 0:
                # Only nearby negation/advisory wording cancels this phrase. A disclaimer
                # elsewhere in a long chat must not suppress a separate risky request.
                prefix=norm[max(0,idx-90):idx]
                negated=any(marker in prefix for marker in NEGATIONS)
                if negated:
                    continue
                conf=.78 if lang==language else .64
                found.append(LanguageSignal(pattern_id,category,severity,phrase,lang,conf,_excerpt(text,phrase)))
                break
    # Deduplicate categories and cap repeated phrases from one message.
    unique=[]; seen=set()
    for signal in found:
        if signal.category not in seen:
            unique.append(signal); seen.add(signal.category)
    limitations=("Rule-based phrase analysis; not a trained language model.",
                 "Sheng, code-switching, spelling variation and sarcasm are not comprehensively covered.",
                 "Brand names and ordinary payment instructions are not treated as fraud by themselves.",
                 "Signals are contextual evidence only and do not produce a seller verdict.")
    return LanguageAnalysis(language,lang_conf,tuple(unique),tuple(s.category for s in unique),limitations)
