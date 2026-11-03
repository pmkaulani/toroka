"""Recovery assistant (blueprint 4.10): calm triage after someone has already paid or shared something.

Asks only what is needed, never asks for secrets, never promises recovery.
"""
from __future__ import annotations

from dataclasses import dataclass

QUESTIONS = {
    "paid": "Did you send money (via M-PESA, Till, or bank)?",
    "shared_credentials": "Did you share a PIN, password or one-time code?",
    "installed_app": "Did you install an app or open a link at their request?",
    "sent_id_documents": "Did you send photos or numbers from identity documents?",
}

QUESTIONS_SW = {
    "paid": "Je, ulituma pesa (kupitia M-PESA, Till au benki)?",
    "shared_credentials": "Je, ulishiriki PIN, nenosiri au msimbo wa mara moja?",
    "installed_app": "Je, ulisakinisha programu au kufungua kiungo kwa ombi lao?",
    "sent_id_documents": "Je, ulituma picha au nambari za hati za utambulisho?",
}

STEPS_SW = {
    "Stop any further payments to this person, even if they promise a refund or ask for a 'release' fee.":
        "Sitisha malipo yote zaidi kwa mtu huyu, hata wakiahidi kurejesha au kuomba ada ya 'kutoa mzigo'.",
    "Contact your mobile-money provider or bank through the number on its official website, app or card. Ask what they can do and what they need from you.":
        "Wasiliana na mtoaji wako wa pesa za simu (Safaricom 234/100) au benki kupitia nambari rasmi. Waeleze kilichotokea na uombe kurejeshewa pesa.",
    "Keep the original messages, the payment confirmation and the numbers involved. Do not delete them.":
        "Hifadhi jumbe za awali, SMS ya uthibitisho wa malipo na nambari zote zilizohusika. Usizifute.",
    "Change the PIN or password now, on your own device, using the official app or channel. Do the same anywhere you reused it.":
        "Badilisha PIN au nenosiri sasa hivi kwenye kifaa chako kwa kutumia programu au njia rasmi.",
    "Check your recent transactions and sign out other sessions where you can.":
        "Kagua miamala yako ya hivi karibuni na ujiondoe kwenye vipindi vingine popote unapoona.",
    "Disconnect the phone from the internet, uninstall the app and run your phone's built-in security check. If unsure, ask your provider's shop to check it.":
        "Tenganisha simu na intaneti, ondoa programu hiyo na uendeshe ukaguzi wa usalama wa simu yako.",
    "From a different, safe device, change your important passwords.":
        "Kutoka kwa kifaa kingine salama, badilisha nywila zako zote muhimu.",
    "Tell the organisation that issued the document, and watch for loans or SIM registrations you did not make.":
        "Waarifu shirika lililotoa kitambulisho hicho, na uangalie kama kuna mikopo au usajili wa laini za SIM usiojua.",
    "Report it through the official channels you find yourself (your provider, and the police). Reporting does not guarantee recovery, but it creates a record.":
        "Ripoti kupitia njia rasmi (Safaricom kwa 333 na Polisi kupata nambari ya OB). Kutoa ripoti kunaunda kumbukumbu rasmi.",
    "Warn people close to you; scammers often try the same script again, including 'recovery' offers that ask for fees.":
        "Watahadharishe watu walio karibu nawe; walaghai mara nyingi hurudia mbinu hiyohiyo, ikiwa ni pamoja na kujifanya wanaweza 'kukusaidia kurudisha pesa kwa ada'.",
}


@dataclass
class Step:
    text: str
    priority: int


def triage(answers: dict[str, bool | None], language: str = "en") -> dict:
    is_sw = language == "sw"
    q_dict = QUESTIONS_SW if is_sw else QUESTIONS
    unknown = [k for k in QUESTIONS if answers.get(k) is None]
    steps: list[Step] = []
    if answers.get("paid"):
        steps += [Step("Stop any further payments to this person, even if they promise a refund or ask for a 'release' fee.", 1),
                  Step("Contact your mobile-money provider or bank through the number on its official website, app or card. Ask what they can do and what they need from you.", 1),
                  Step("Keep the original messages, the payment confirmation and the numbers involved. Do not delete them.", 2)]
    if answers.get("shared_credentials"):
        steps += [Step("Change the PIN or password now, on your own device, using the official app or channel. Do the same anywhere you reused it.", 1),
                  Step("Check your recent transactions and sign out other sessions where you can.", 2)]
    if answers.get("installed_app"):
        steps += [Step("Disconnect the phone from the internet, uninstall the app and run your phone's built-in security check. If unsure, ask your provider's shop to check it.", 1),
                  Step("From a different, safe device, change your important passwords.", 2)]
    if answers.get("sent_id_documents"):
        steps += [Step("Tell the organisation that issued the document, and watch for loans or SIM registrations you did not make.", 2)]
    if any(answers.get(k) for k in QUESTIONS):
        steps += [Step("Report it through the official channels you find yourself (your provider, and the police). Reporting does not guarantee recovery, but it creates a record.", 3),
                  Step("Warn people close to you; scammers often try the same script again, including 'recovery' offers that ask for fees.", 3)]
    steps.sort(key=lambda s: s.priority)

    reassurance = "Hili si kosa lako. Walaghai wamebobea katika mambo haya." if is_sw else "This is not your fault. Scammers are practised at this."
    limits = "Hatuwezi kurejesha malipo moja kwa moja wala kuahidi kurudishiwa fedha. Hatutawahi kukuuliza PIN, nenosiri wala msimbo." if is_sw else "We cannot reverse payments and cannot promise a refund. We will never ask you for a PIN, password or code."

    step_outs = []
    for s in steps:
        txt = STEPS_SW.get(s.text, s.text) if is_sw else s.text
        step_outs.append({"text": txt, "priority": s.priority})

    return {"questions": [{"id": k, "text": q_dict[k]} for k in unknown],
            "steps": step_outs,
            "reassurance": reassurance,
            "limits": limits}
