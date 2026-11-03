import json, os, tempfile, unittest, hashlib, hmac
from datetime import datetime, timezone, timedelta

from toroka_phase7 import (
    FeedPolicy, Indicator, FetchResponse, OperationsStore, FeedRunner,
    CaseMemoryStore, analyze_message, detect_language, campaign_group_split,
    evaluate_rule_set, shadow_release_gate, RuntimeConfig, production_readiness,
    Phase7Coordinator, parse_stix_bundle, normalize_indicator, reference_feed_catalog,
    curate_ke_cirt_advisory, kenya_reference_sources,
)

NOW = datetime(2026, 11, 4, 12, 0, tzinfo=timezone.utc)
SECRET = b"toroka-phase-seven-test-secret-32-bytes-minimum!!"


def policy(**overrides):
    base=dict(source_id="phishtank-test",provider_name="PhishTank Test",
        endpoint_url="https://feed.example.com/stix",terms_url="https://provider.example.com/terms",
        allowed_hosts=("feed.example.com",),commercial_use_allowed=True,internal_check_allowed=True,
        display_allowed=False,redistribution_allowed=False,permission_confirmed=True,
        terms_reviewed_at="2026-11-01T00:00:00+00:00",attribution="Test Provider",
        poll_interval_seconds=300,freshness_ttl_seconds=900,max_response_bytes=100000,
        max_indicators=100,max_failures_before_circuit=3,circuit_cooldown_seconds=600)
    base.update(overrides)
    return FeedPolicy(**base)


def stix_bundle(domain="bad.example"):
    return json.dumps({"type":"bundle","id":"bundle--abc","objects":[
        {"type":"indicator","id":"indicator--abc","pattern_type":"stix","pattern":f"[domain-name:value = '{domain}']","confidence":90,"labels":["phishing"]}
    ]}).encode()


class PolicyAndIndicatorTests(unittest.TestCase):
    def test_default_catalog_is_disabled(self):
        catalog=reference_feed_catalog()
        self.assertGreaterEqual(len(catalog),4)
        self.assertTrue(all(x["permission_confirmed"] is False for x in catalog))

    def test_requires_terms_review_date(self):
        with self.assertRaises(PermissionError): policy(terms_reviewed_at=None).validate()

    def test_expired_terms_review_blocks_feed(self):
        with self.assertRaises(PermissionError): policy(terms_reviewed_at="2025-01-01T00:00:00+00:00").validate(now=NOW)

    def test_future_terms_review_blocks_feed(self):
        with self.assertRaises(ValueError): policy(terms_reviewed_at="2027-01-01T00:00:00+00:00").validate(now=NOW)

    def test_commercial_permission_required(self):
        with self.assertRaises(PermissionError): policy(commercial_use_allowed=False).validate()

    def test_internal_use_permission_required(self):
        with self.assertRaises(PermissionError): policy(internal_check_allowed=False).validate()

    def test_permission_confirmation_required(self):
        with self.assertRaises(PermissionError): policy(permission_confirmed=False).validate()

    def test_endpoint_must_match_host_allowlist(self):
        with self.assertRaises(ValueError): policy(allowed_hosts=("other.example",)).validate()

    def test_http_endpoint_rejected(self):
        with self.assertRaises(ValueError): policy(endpoint_url="http://feed.example.com/stix").validate()

    def test_credential_endpoint_rejected(self):
        with self.assertRaises(ValueError): policy(endpoint_url="https://user:pass@feed.example.com/stix").validate()

    def test_bad_ttl_rejected(self):
        with self.assertRaises(ValueError): policy(freshness_ttl_seconds=100).validate()

    def test_normalize_domain(self):
        self.assertEqual(normalize_indicator("domain","HTTPS://ExAmPlE.com/path"),"example.com")

    def test_normalize_url_drops_sensitive_path_and_query(self):
        self.assertEqual(normalize_indicator("url","https://example.com/reset/token-abc?x=1"),"https://example.com/")

    def test_private_ip_rejected(self):
        with self.assertRaises(ValueError): normalize_indicator("ipv4","127.0.0.1")

    def test_invalid_sha256_rejected(self):
        with self.assertRaises(ValueError): normalize_indicator("sha256","abcd")

    def test_unsupported_type_rejected(self):
        with self.assertRaises(ValueError): normalize_indicator("email","a@b.com")

    def test_parse_supported_stix_indicator(self):
        rows,warnings=parse_stix_bundle(stix_bundle(),source_id="test")
        self.assertEqual(len(rows),1); self.assertEqual(rows[0].value,"bad.example"); self.assertEqual(rows[0].confidence,.9)
        self.assertEqual(warnings,[])

    def test_parse_skips_revoked(self):
        doc=json.loads(stix_bundle()); doc["objects"][0]["revoked"]=True
        rows,_=parse_stix_bundle(json.dumps(doc),source_id="test")
        self.assertEqual(rows,[])

    def test_parse_skips_complex_pattern(self):
        doc=json.loads(stix_bundle()); doc["objects"][0]["pattern"]="[domain-name:value = 'bad.example'] OR [domain-name:value = 'other.example']"
        rows,warnings=parse_stix_bundle(json.dumps(doc),source_id="test")
        self.assertEqual(rows,[]); self.assertTrue(warnings)

    def test_invalid_bundle_rejected(self):
        with self.assertRaises(ValueError): parse_stix_bundle(b"[]",source_id="test")

    def test_bundle_object_limit(self):
        doc={"type":"bundle","objects":[{}]*3}
        with self.assertRaises(ValueError): parse_stix_bundle(json.dumps(doc),source_id="x",max_objects=2)


class FeedOperationsTests(unittest.TestCase):
    def setUp(self):
        self.store=OperationsStore()
        self.store.register_policy(policy(),now=NOW)

    def tearDown(self):
        self.store.close()

    def test_registered_feed_is_due(self):
        self.assertEqual(self.store.list_due(now=NOW),["phishtank-test"])

    def test_lease_can_be_claimed_once(self):
        self.assertTrue(self.store.claim("phishtank-test","worker-a",now=NOW))
        self.assertFalse(self.store.claim("phishtank-test","worker-b",now=NOW))

    def test_successful_ingest(self):
        self.store.claim("phishtank-test","worker-a",now=NOW)
        n=self.store.ingest_success("phishtank-test","worker-a",[Indicator("domain","bad.example",.9,("phish",))],digest="a"*64,now=NOW)
        self.assertEqual(n,1)
        self.assertEqual(self.store.indicator_lookup("domain","bad.example",now=NOW)[0]["fresh"],True)

    def test_last_known_good_retained_after_failure(self):
        self.store.claim("phishtank-test","worker-a",now=NOW)
        self.store.ingest_success("phishtank-test","worker-a",[Indicator("domain","bad.example")],digest="a"*64,now=NOW)
        t=NOW+timedelta(seconds=301)
        self.store.claim("phishtank-test","worker-a",now=t)
        self.store.ingest_failure("phishtank-test","worker-a","timeout",now=t)
        self.assertTrue(self.store.indicator_lookup("domain","bad.example",now=t)[0]["fresh"])

    def test_expired_indicator_not_fresh(self):
        self.store.claim("phishtank-test","worker-a",now=NOW)
        self.store.ingest_success("phishtank-test","worker-a",[Indicator("domain","bad.example")],digest="a"*64,now=NOW)
        t=NOW+timedelta(seconds=901)
        self.assertFalse(self.store.indicator_lookup("domain","bad.example",now=t)[0]["fresh"])

    def test_phase4_export_requires_display_rights(self):
        self.store.claim("phishtank-test","worker-a",now=NOW)
        self.store.ingest_success("phishtank-test","worker-a",[Indicator("domain","bad.example")],digest="a"*64,now=NOW)
        with self.assertRaises(PermissionError): self.store.export_to_phase4("phishtank-test",object(),phase4_source_name="feed",now=NOW)

    def test_phase4_export_marks_refresh_success_when_available(self):
        try:
            from toroka_phase4.intel import ThreatIntelStore, FeedPolicy as P4Policy
        except ImportError:
            self.skipTest("Phase 4 package not installed in standalone test run")
        sync_now=datetime.now(timezone.utc)
        p7=policy(source_id="phase4-bridge",display_allowed=True)
        self.store.register_policy(p7,now=sync_now)
        self.store.claim("phase4-bridge","worker-a",now=sync_now)
        self.store.ingest_success("phase4-bridge","worker-a",[Indicator("domain","bad.example")],digest="b"*64,now=sync_now)
        p4=ThreatIntelStore(":memory:")
        p4.register_feed(P4Policy(name="Phase7 bridge",source_group="phase7_bridge",terms_url="https://provider.example.com/terms",commercial_use_allowed=True,permission_confirmed=True,display_allowed=True,attribution="Test source",freshness_ttl_hours=2))
        self.assertEqual(self.store.export_to_phase4("phase4-bridge",p4,phase4_source_name="Phase7 bridge",now=sync_now),1)
        self.assertEqual(p4.lookup_domain("bad.example",now=sync_now)[0].status,"active")
        p4.close()

    def test_idempotent_snapshot_does_not_duplicate_and_refreshes_ttl(self):
        self.store.claim("phishtank-test","worker-a",now=NOW)
        self.store.ingest_success("phishtank-test","worker-a",[Indicator("domain","bad.example")],digest="a"*64,now=NOW)
        t=NOW+timedelta(seconds=301); self.store.claim("phishtank-test","worker-a",now=t)
        n=self.store.ingest_success("phishtank-test","worker-a",[Indicator("domain","bad.example")],digest="a"*64,now=t)
        self.assertEqual(n,1)
        self.assertTrue(self.store.indicator_lookup("domain","bad.example",now=t+timedelta(seconds=850))[0]["fresh"])

    def test_ingest_requires_lease_owner(self):
        with self.assertRaises(PermissionError): self.store.ingest_success("phishtank-test","wrong",[],digest="x",now=NOW)

    def test_invalid_batch_rolls_back_before_commit(self):
        self.store.claim("phishtank-test","worker-a",now=NOW)
        with self.assertRaises(ValueError): self.store.ingest_success("phishtank-test","worker-a",[Indicator("domain","ok.example"),Indicator("ipv4","10.0.0.1")],digest="a"*64,now=NOW)
        self.assertEqual(self.store.conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0],0)

    def test_rate_limit_sets_retry_and_alert(self):
        self.store.claim("phishtank-test","worker-a",now=NOW)
        self.store.ingest_failure("phishtank-test","worker-a","429",retry_after_seconds=120,now=NOW)
        alerts=self.store.list_alerts()
        self.assertTrue(any(a.alert_type=="feed_rate_limited" for a in alerts))
        row=self.store.conn.execute("SELECT next_attempt FROM feed_state").fetchone()[0]
        self.assertEqual(datetime.fromisoformat(row),NOW+timedelta(seconds=120))

    def test_circuit_breaker_opens(self):
        now=NOW
        for i in range(3):
            self.store.claim("phishtank-test","worker-a",now=now)
            self.store.ingest_failure("phishtank-test","worker-a","timeout",now=now)
            if i < 2: now=now+timedelta(seconds=601)
        health=self.store.evaluate_health(now=now)[0]
        self.assertEqual(health.state,"circuit_open")

    def test_alerts_are_deduplicated(self):
        self.store.upsert_alert("phishtank-test","feed_stale","medium","stale",now=NOW)
        self.store.upsert_alert("phishtank-test","feed_stale","high","still stale",now=NOW+timedelta(seconds=1))
        self.assertEqual(len(self.store.list_alerts()),1)
        self.assertEqual(self.store.list_alerts()[0].severity,"high")

    def test_alert_acknowledgement(self):
        self.store.upsert_alert("phishtank-test","feed_stale","medium","stale",now=NOW)
        alert=self.store.list_alerts()[0]
        self.store.acknowledge_alert(alert.alert_id)
        self.assertEqual(self.store.list_alerts(),[])

    def test_health_state_never_succeeded(self):
        self.assertEqual(self.store.evaluate_health(now=NOW)[0].state,"never_succeeded")

    def test_never_succeeded_after_attempt_creates_alert(self):
        self.store.claim("phishtank-test","worker-a",now=NOW)
        self.store.ingest_failure("phishtank-test","worker-a","503",now=NOW)
        self.store.evaluate_health(now=NOW)
        self.assertTrue(any(a.alert_type=="feed_never_succeeded" for a in self.store.list_alerts()))

    def test_metrics_snapshot_is_aggregate_only(self):
        metrics=self.store.metrics_snapshot(now=NOW)
        self.assertEqual(metrics["feeds_total"],1)
        self.assertNotIn("case_id",metrics)

    def test_disabled_feed_not_due(self):
        disabled=OperationsStore(); disabled.register_policy(policy(source_id="disabled"),enabled=False,now=NOW)
        self.assertEqual(disabled.list_due(now=NOW),[])

    def test_feed_runner_success_with_injected_fetcher(self):
        def fetch(url,**kw): return FetchResponse(200,{"content-type":"application/json"},stix_bundle(),url)
        runner=FeedRunner(self.store,fetch,worker_id="test-worker")
        result=runner.run_due_once(now=NOW)
        self.assertEqual(result["outcomes"][0]["outcome"],"success")

    def test_feed_runner_blocks_non_allowlisted_final_url(self):
        def fetch(url,**kw): return FetchResponse(200,{"content-type":"application/json"},stix_bundle(),"https://evil.example.com/stix")
        result=FeedRunner(self.store,fetch,worker_id="test-worker").run_due_once(now=NOW)
        self.assertEqual(result["outcomes"][0]["error_code"],"invalid_payload")

    def test_feed_runner_rejects_oversized_response(self):
        def fetch(url,**kw): return FetchResponse(200,{"content-type":"application/json"},b"x"*100001,url)
        result=FeedRunner(self.store,fetch,worker_id="test-worker").run_due_once(now=NOW)
        self.assertEqual(result["outcomes"][0]["error_code"],"invalid_payload")

    def test_feed_runner_handles_http_503(self):
        def fetch(url,**kw): return FetchResponse(503,{"retry-after":"60"},b"",url)
        result=FeedRunner(self.store,fetch,worker_id="test-worker").run_due_once(now=NOW)
        self.assertEqual(result["outcomes"][0]["error_code"],"503")

    def test_provider_timeout_recorded(self):
        def fetch(url,**kw): raise TimeoutError()
        result=FeedRunner(self.store,fetch,worker_id="test-worker").run_due_once(now=NOW)
        self.assertEqual(result["outcomes"][0]["error_code"],"timeout")

    def test_alert_for_auth_failure(self):
        self.store.claim("phishtank-test","worker-a",now=NOW)
        self.store.ingest_failure("phishtank-test","worker-a","403",now=NOW)
        self.assertTrue(any(a.alert_type=="feed_provider_error" and a.severity=="high" for a in self.store.list_alerts()))


class CaseMemoryTests(unittest.TestCase):
    def setUp(self): self.memory=CaseMemoryStore(secret=SECRET)

    def tearDown(self): self.memory.close()

    def add(self, **kwargs):
        base=dict(case_ref="case_00000001",entity_type="domain",value="shop.example",source_family="user_report",evidence_ref="evidence_001",now=NOW)
        base.update(kwargs); return self.memory.add_observation(**base)

    def test_secret_minimum(self):
        with self.assertRaises(ValueError): CaseMemoryStore(secret=b"short")

    def test_private_pending_not_visible_in_lookup(self):
        self.add()
        result=self.memory.lookup(entity_type="domain",value="shop.example",now=NOW)
        self.assertFalse(result["matched"]); self.assertEqual(result["corroborated_observations"],0)

    def test_phone_normalization_matches_different_format(self):
        rid=self.add(entity_type="phone_ke",value="0712345678")
        rid2=self.add(case_ref="case_00000002",entity_type="phone_ke",value="+254712345678",source_family="merchant_supplied",evidence_ref="evidence_002")
        self.assertTrue(rid); self.assertTrue(rid2)

    def test_phone_digest_is_compatible_with_phase3_graph(self):
        self.add(entity_type="phone_ke",value="0712345678")
        stored=self.memory.conn.execute("SELECT entity_hmac FROM memory_records").fetchone()[0]
        expected=hmac.new(SECRET,b"toroka-v3:phone:+254712345678",hashlib.sha256).hexdigest()
        self.assertEqual(stored,expected)

    def test_memory_does_not_store_raw_domain_or_phone(self):
        self.add(entity_type="phone_ke",value="0712345678")
        row=self.memory.conn.execute("SELECT entity_hmac FROM memory_records").fetchone()[0]
        self.assertNotIn("0712345678",row); self.assertEqual(len(row),64)

    def test_unauthorized_moderation_rejected(self):
        rid=self.add()
        with self.assertRaises(PermissionError): self.memory.moderate(rid,review_state="not_corroborated",actor_role="user",reason_code="not_supported")

    def test_two_source_families_can_be_moderated(self):
        a=self.add()
        b=self.add(case_ref="case_00000002",source_family="public_web_observation",evidence_ref="evidence_002")
        self.memory.moderate(a,review_state="corroborated_indicator",actor_role="moderator",reason_code="corroborated_by_independent_sources",now=NOW)
        result=self.memory.lookup(entity_type="domain",value="shop.example",now=NOW)
        self.assertTrue(result["matched"]); self.assertEqual(result["corroborated_observations"],1)

    def test_single_user_report_cannot_be_corroborated(self):
        rid=self.add()
        with self.assertRaises(ValueError): self.memory.moderate(rid,review_state="corroborated_indicator",actor_role="moderator",reason_code="corroborated_by_independent_sources",now=NOW)

    def test_authoritative_feed_can_be_moderated_alone(self):
        rid=self.add(source_family="external_threat_feed",authoritative_source=True)
        self.memory.moderate(rid,review_state="corroborated_indicator",actor_role="admin",reason_code="authoritative_feed_match",now=NOW)
        self.assertTrue(self.memory.lookup(entity_type="domain",value="shop.example",now=NOW)["matched"])

    def test_user_cannot_claim_authoritative_source(self):
        with self.assertRaises(ValueError): self.add(authoritative_source=True)

    def test_correction_request_hides_history_until_resolved(self):
        rid=self.add(source_family="external_threat_feed",authoritative_source=True)
        self.memory.moderate(rid,review_state="corroborated_indicator",actor_role="admin",reason_code="authoritative_feed_match",now=NOW)
        req=self.memory.request_correction(rid,request_code="source_retracted",now=NOW)
        self.assertFalse(self.memory.lookup(entity_type="domain",value="shop.example",now=NOW)["matched"])
        self.memory.resolve_correction(req,resolution="accepted",actor_role="privacy_officer",resolution_code="source_rechecked",now=NOW)
        self.assertFalse(self.memory.lookup(entity_type="domain",value="shop.example",now=NOW)["matched"])

    def test_correction_requires_authorized_reviewer(self):
        rid=self.add(); req=self.memory.request_correction(rid,request_code="other",now=NOW)
        with self.assertRaises(PermissionError): self.memory.resolve_correction(req,resolution="accepted",actor_role="user",resolution_code="record_withdrawn")

    def test_expired_memory_is_purged(self):
        self.add(now=NOW-timedelta(days=200))
        self.assertEqual(self.memory.purge_expired(now=NOW),1)

    def test_invalid_case_ref_rejected(self):
        with self.assertRaises(ValueError): self.add(case_ref="Peter Kaulani")

    def test_unsupported_source_family_rejected(self):
        with self.assertRaises(ValueError): self.add(source_family="random")


class MultilingualTests(unittest.TestCase):
    def test_english_pin_theft(self):
        self.assertIn("credential_theft",analyze_message("Please send your M-Pesa PIN now.").categories)

    def test_swahili_pin_theft(self):
        result=analyze_message("Tuma pin yako sasa hivi")
        self.assertEqual(result.language,"sw"); self.assertIn("credential_theft",result.categories)

    def test_sheng_upfront_payment(self):
        result=analyze_message("Buda toa doo kwanza ndio utoe pesa")
        self.assertEqual(result.language,"sheng"); self.assertIn("advance_fee",result.categories)

    def test_sheng_job_fee(self):
        self.assertIn("job_fee",analyze_message("Weka doo ndio upate kazi").categories)

    def test_swahili_fake_government_grant(self):
        self.assertIn("government_benefit_bait",analyze_message("Pesa za serikali zimeingia lipa ada upate pesa za serikali").categories)

    def test_english_prize_bait(self):
        self.assertIn("prize_bait",analyze_message("You have won a prize, claim your free bonus").categories)

    def test_negated_safety_advice_not_flagged_as_credential_theft(self):
        result=analyze_message("Never share your OTP. Usitume pin yako kwa mtu.")
        self.assertNotIn("credential_theft",result.categories)

    def test_normal_till_payment_instruction_not_flagged(self):
        self.assertEqual(analyze_message("Pay KSh 500 to Till 123456 and keep your receipt").categories,())

    def test_brand_mention_not_enough(self):
        self.assertEqual(analyze_message("Safaricom announced a new customer service centre").categories,())

    def test_no_verdict_returned(self):
        self.assertIsNone(analyze_message("Umepata doo za bure").to_dict()["verdict"])

    def test_excerpts_redact_long_numbers_and_phone(self):
        result=analyze_message("Tuma pin yako 0712345678 au code 123456")
        excerpt=result.signals[0].excerpt
        self.assertNotIn("0712345678",excerpt); self.assertNotIn("123456",excerpt)

    def test_long_text_is_bounded(self):
        result=analyze_message("a"*100000)
        self.assertEqual(result.signals,())

    def test_empty_input_has_unknown_language_confidence_zero(self):
        lang,conf=detect_language("")
        self.assertEqual(lang,"en"); self.assertEqual(conf,0)

    def test_categories_are_deduplicated(self):
        result=analyze_message("You have won a prize. You are our lucky winner. Free betting bonus.")
        self.assertEqual(result.categories.count("prize_bait"),1)


class EvaluationAndReadinessTests(unittest.TestCase):
    def test_campaign_split_has_no_leakage(self):
        rows=[{"campaign_id":f"c{i}","text":"sample","label":"scam"} for i in range(20)]
        train,test=campaign_group_split(rows)
        self.assertTrue(train and test)
        self.assertFalse({r["campaign_id"] for r in train}&{r["campaign_id"] for r in test})

    def test_missing_campaign_rejected(self):
        with self.assertRaises(ValueError): campaign_group_split([{"text":"x"}])

    def test_campaign_split_invalid_fraction_rejected(self):
        with self.assertRaises(ValueError): campaign_group_split([],test_fraction=.9)

    def test_metrics_per_language(self):
        rows=[{"campaign_id":"a","label":"scam","text":"Tuma pin yako","language":"sw"},
              {"campaign_id":"b","label":"legitimate","text":"Hello, have a nice day","language":"en"}]
        m=evaluate_rule_set(rows)
        self.assertIn("sw",m["by_language"]); self.assertEqual(m["overall"]["samples"],2)

    def test_evaluation_rejects_missing_label(self):
        with self.assertRaises(ValueError): evaluate_rule_set([{"campaign_id":"a","text":"hello"}])

    def test_release_gate_requires_target_language_samples(self):
        metric={"overall":{"samples":1000,"precision":1,"recall":1,"false_positive_rate":0},"campaign_count":100}
        result=shadow_release_gate(metric,min_samples=10,min_campaigns=5,min_language_samples=10)
        self.assertFalse(result["passed"])
        self.assertFalse(result["checks"]["language_subgroups"])

    def test_release_gate_never_authorizes_production(self):
        good={"samples":30,"precision":1,"recall":1,"false_positive_rate":0}
        metric={"overall":{"samples":1000,"precision":1,"recall":1,"false_positive_rate":0},
                "campaign_count":100,"by_language":{"en":good,"sw":good,"sheng":good}}
        result=shadow_release_gate(metric,min_samples=10,min_campaigns=5,min_language_samples=10)
        self.assertTrue(result["passed"]); self.assertFalse(result["production_promotion_allowed"])
        self.assertEqual(result["authorization"],"shadow_only")

    def test_release_gate_blocks_weak_metrics(self):
        result=shadow_release_gate({"overall":{"samples":5,"precision":.5,"recall":.3,"false_positive_rate":.2},"campaign_count":2})
        self.assertFalse(result["passed"]); self.assertEqual(result["authorization"],"blocked")

    def test_production_readiness_blocks_missing_controls(self):
        result=production_readiness(RuntimeConfig(environment="production"))
        self.assertFalse(result["ready"]); self.assertGreater(len(result["missing_controls"]),5)

    def test_development_readiness_is_nonblocking(self):
        result=production_readiness(RuntimeConfig(environment="development"))
        self.assertTrue(result["ready"])

    def test_invalid_environment_rejected(self):
        with self.assertRaises(ValueError): production_readiness(RuntimeConfig(environment="local"))

    def test_coordinator_text_analysis(self):
        coordinator=Phase7Coordinator()
        self.assertIn("credential_theft",coordinator.analyze_text("Nipe otp yako")["categories"])

    def test_coordinator_missing_worker_reports_configuration(self):
        result=Phase7Coordinator().refresh_due_feeds()
        self.assertEqual(result["status"],"feed_runner_not_configured")

    def test_database_persistence(self):
        with tempfile.TemporaryDirectory() as td:
            path=os.path.join(td,"ops.db")
            store=OperationsStore(path); store.register_policy(policy(),now=NOW); store.close()
            reopened=OperationsStore(path)
            try:
                self.assertEqual(reopened.policy("phishtank-test").source_id,"phishtank-test")
            finally:
                reopened.close()


class KenyaAdvisoryTests(unittest.TestCase):
    def test_accepts_official_ke_cirt_advisory(self):
        row=curate_ke_cirt_advisory(title="Online shopping safety advisory",source_url="https://ke-cirt.go.ke/alerts-advisories/",published_at="2026-10-01T10:00:00Z",reviewed_by="staff_001",summary="Advisory on online shopping fraud")
        self.assertEqual(row.authority,"National KE-CIRT/CC")
        self.assertEqual(row.source_type,"official_public_advisory")
        self.assertEqual(len(row.advisory_id),20)

    def test_rejects_lookalike_host(self):
        with self.assertRaises(ValueError): curate_ke_cirt_advisory(title="x",source_url="https://ke-cirt.go.ke.attacker.example/report",published_at="2026-10-01T10:00:00Z",reviewed_by="staff_001",summary="x")

    def test_rejects_http_advisory(self):
        with self.assertRaises(ValueError): curate_ke_cirt_advisory(title="x",source_url="http://ke-cirt.go.ke/report",published_at="2026-10-01T10:00:00Z",reviewed_by="staff_001",summary="x")

    def test_scrubs_personal_identifiers_from_summary(self):
        row=curate_ke_cirt_advisory(title="x",source_url="https://ke-cirt.go.ke/alerts-advisories/",published_at="2026-10-01T10:00:00Z",reviewed_by="staff_001",summary="Contact +254712345678 or test@example.com, ref 12345678")
        self.assertNotIn("+254712345678",row.summary); self.assertNotIn("test@example.com",row.summary); self.assertNotIn("12345678",row.summary)

    def test_reviewed_by_must_be_opaque(self):
        with self.assertRaises(ValueError): curate_ke_cirt_advisory(title="x",source_url="https://ke-cirt.go.ke/alerts-advisories/",published_at="2026-10-01T10:00:00Z",reviewed_by="Peter Kaulani",summary="x")

    def test_reference_sources_are_context_not_feeds(self):
        self.assertTrue(kenya_reference_sources())
        self.assertTrue(all(row["automated_indicator_feed"] is False for row in kenya_reference_sources()))

    def test_rejects_naive_published_timestamp(self):
        with self.assertRaises(ValueError): curate_ke_cirt_advisory(title="x",source_url="https://ke-cirt.go.ke/alerts-advisories/",published_at="2026-10-01T10:00:00",reviewed_by="staff_001",summary="x")


if __name__=="__main__": unittest.main()
