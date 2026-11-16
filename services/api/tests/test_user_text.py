from app.user_text import scrub_reply, INTERNAL


def test_internal_sentences_are_removed_and_the_rest_kept():
    t = "I checked **@kicks.nairobi, TikTok**. Live search not run because TAVILY_API_KEY is not configured. Some sources were unavailable or not configured: Google Places, Scrape Creators, Weir.\n\nAsk for the registered business name."
    s = scrub_reply(t)
    assert "TAVILY" not in s and "Weir" not in s and "Google Places" not in s and "kicks.nairobi" in s and "registered business name" in s


def test_clean_text_is_untouched():
    t = "I cannot yet tell whether this account is real. Here is how to check before you pay."
    assert scrub_reply(t) == t


def test_twenty_sample_answers_have_no_internals_after_scrub():
    samples = [
        "Live search not run because TAVILY_API_KEY is not configured. Please be careful.",
        "Scrape Creators was unable to fetch profile. Verify the handle manually.",
        "Weir phone lookup failed. In this run, we could not find additional signals.",
        "URLScan returned no match for this domain. The domain was registered recently.",
        "VirusTotal detected 0 malicious engines. Proceed with caution.",
        "Google Places API key is not configured. Ask the seller for their physical location.",
        "Gemini synthesis completed with fallback. Here is what we found.",
        "OpenAI provider circuit breaker tripped. Check bank details before sending money.",
        "The GEMINI_API_KEY environment variable is missing. Keep conversations on platform.",
        "Toroka internal intelligence reported 2 flags. Do not pay upfront.",
        "Provider status: not_configured for external search. Verify the company registration.",
        "I could not establish whether this is safe from the checks available in this run.",
        "Because TAVILY_SEARCH_API_KEY is unset, live search was skipped. Check registration with BRS.",
        "Some sources were unavailable: ScrapeCreators, Weir. Ask for payment on delivery.",
        "Breaker open for provider endpoint. Never share your M-Pesa PIN.",
        "External search provider failed. Always confirm identity via official channels.",
        "API_KEY expired. The seller has no verifiable physical store.",
        "Check available in this run showed inconclusive results. Verify phone number.",
        "Google Places search did not find this business. Require in-person inspection.",
        "Tavily search returned 0 items. In this run, no verified records were matched.",
    ]
    for sample in samples:
        scrubbed = scrub_reply(sample)
        assert not INTERNAL.search(scrubbed), f"Found leak in scrubbed text: {scrubbed!r}"
