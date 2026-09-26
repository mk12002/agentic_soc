"""Feature verification: proves each feature in docs/FEATURES.md works, and writes docs/FEATURE_VERIFICATION.md.

    python scripts/verify_features.py              # automated tests + evaluations
    python scripts/verify_features.py --browser    # + real server and browser tour (needs Node and Chrome/Edge)
    python scripts/verify_features.py --engine     # + phishing ML engine suite (needs requirements/phishing.txt)

Every feature is mapped to the tests that exercise it. A feature is VERIFIED only if all of its tests pass;
the report lists the exact tests, so anyone can re-run one (`pytest soc_platform/tests/<file>::<test>`).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "FEATURE_VERIFICATION.md"
T = "soc_platform/tests/"

# (area, feature, [tests]) - tests are "file.py::test_name" under soc_platform/tests
FEATURES: list[tuple[str, str, list[str]]] = [
    # ---------------------------------------------------------------- platform
    ("Platform", "Console serves all screens; every screen's API works for the right roles (client-demo walkthrough)",
     ["test_demo_walkthrough.py::test_full_client_demo", "test_api.py::test_siem_push_and_ui"]),
    ("Platform", "Overview dashboard figures consistent with records; measured latency",
     ["test_demo_walkthrough.py::test_full_client_demo"]),
    ("Platform", "Asset resolution across tools (deterministic → fuzzy → queue → override)",
     ["test_core_context.py::test_deterministic_cross_tool_match_on_serial", "test_core_context.py::test_conflicting_serial_prevents_merge",
      "test_core_context.py::test_probabilistic_match_requires_multiple_signals", "test_core_context.py::test_ambiguous_goes_to_unresolved_queue_not_merged",
      "test_core_context.py::test_stale_ip_is_ignored", "test_connectors.py::test_cross_tool_asset_resolution_collapses_same_hosts",
      "test_resolution_scale.py::test_no_false_merges_and_bounded_splits"]),
    ("Platform", "Identity resolution across tools (UPN / SAM / aliases / renames / built-in accounts)",
     ["test_identity_scale.py::test_identities_never_falsely_merged", "test_identity_scale.py::test_alias_and_sam_seen_before_directory_collapse_into_one_person",
      "test_identity_scale.py::test_two_directory_users_are_never_merged_even_when_a_record_bridges_them"]),
    ("Platform", "Unified timeline and relation graph", ["test_core_context.py::test_event_links_resolved_entities_and_timeline"]),
    ("Platform", "Explainability: claims cite evidence, uncited claims dropped, insufficient evidence flagged",
     ["test_core_context.py::test_grounded_drops_uncited_claims_and_logs", "test_core_context.py::test_grounded_insufficient_evidence_and_budget",
      "test_feature_checks.py::test_phishing_verdict_is_explained_with_counterfactual_and_citations"]),
    ("Platform", "Autonomy policy L0-L4, recommend-only default, destructive / VIP / kill-switch caps, blast radius",
     ["test_core_governance.py::test_default_posture_is_recommend_only", "test_core_governance.py::test_destructive_and_vip_and_killswitch_cap_autonomy",
      "test_core_governance.py::test_blast_radius_limits"]),
    ("Platform", "Approvals, four-eyes, separation of duties, policy change control",
     ["test_core_governance.py::test_agent_request_waits_for_human_approval", "test_core_governance.py::test_lead_approval_executes_and_audits",
      "test_core_governance.py::test_requester_cannot_self_approve_four_eyes", "test_core_governance.py::test_analyst_request_of_normal_action_is_explicit_approval",
      "test_core_governance.py::test_policy_change_needs_different_approver", "test_api.py::test_policy_change_control_and_kill_switch"]),
    ("Platform", "Action layer: preconditions, idempotency, rollback, failure records, cross-case de-duplication",
     ["test_core_governance.py::test_failed_precondition_blocks", "test_core_governance.py::test_idempotency_on_replay",
      "test_core_governance.py::test_l4_executes_autonomously_and_rollback_uses_reverse", "test_core_governance.py::test_execution_failure_is_recorded",
      "test_core_governance.py::test_same_containment_from_two_cases_is_one_approval",
      "test_core_governance.py::test_same_host_described_differently_is_still_one_approval",
      "test_core_governance.py::test_same_short_name_with_different_device_ids_is_not_merged"]),
    ("Platform", "Durable kill switch", ["test_access_security.py::test_kill_switch_is_durable_and_permissioned"]),
    ("Platform", "Hash-chained append-only audit log",
     ["test_core_governance.py::test_audit_chain_verifies_and_detects_tampering", "test_core_governance.py::test_audit_orm_refuses_update_and_delete",
      "test_core_governance.py::test_audit_rejects_unknown_actor_type", "test_api.py::test_reports_and_audit_chain"]),
    # ---------------------------------------------------------------- security
    ("Security", "Authentication: forged / expired / unknown-role tokens rejected",
     ["test_resilience_security.py::test_forged_and_expired_tokens_rejected", "test_resilience_security.py::test_unknown_role_claims_grant_nothing",
      "test_api.py::test_auth_required_and_rbac"]),
    ("Security", "Domain-scoped RBAC (roles from Entra claims, platform grants, scoped lists and decisions)",
     ["test_access_security.py::test_domain_scoped_roles_from_entra_style_claims", "test_access_security.py::test_role_grants_are_audited_scoped_expiring_and_never_self_granted",
      "test_access_security.py::test_scoped_users_only_see_and_decide_their_domain_actions", "test_access_security.py::test_http_hardening_scope_body_limit_health_and_streams"]),
    ("Security", "Step-up MFA for decisions", ["test_access_security.py::test_step_up_mfa_required_for_decisions_when_enforced"]),
    ("Security", "Service-account API keys (hashed, expiring, cannot approve)", ["test_access_security.py::test_service_account_keys_are_hashed_expiring_and_cannot_approve"]),
    ("Security", "Token and session revocation, logout, access log", ["test_access_security.py::test_token_and_session_revocation",
                                                                      "test_access_security.py::test_http_domain_scoping_mfa_keys_logout_access_log"]),
    ("Security", "Break-glass (sealed, audited, alerted)", ["test_access_security.py::test_break_glass_requires_sealed_secret_and_is_audited_and_alerted"]),
    ("Security", "Encryption at rest with rotation and tamper detection", ["test_access_security.py::test_encryption_at_rest_roundtrip_rotation_and_tamper"]),
    ("Security", "Retention with legal hold; audit export", ["test_access_security.py::test_retention_prunes_copies_but_keeps_legal_hold_and_audits"]),
    ("Security", "Web hardening: CSP, headers, rate limiting, stream-level body cap", ["test_api.py::test_security_headers_csp_and_limits",
                                                                                     "test_access_security.py::test_rate_limit_is_per_client_not_per_token",
                                                                                     "test_access_security.py::test_http_hardening_scope_body_limit_health_and_streams"]),
    ("Security", "LLM safety: PII pseudonymised before any model call; prompt injection cannot create claims or actions",
     ["test_core_context.py::test_redaction_pseudonymises_internal_people_but_keeps_iocs", "test_resilience_security.py::test_redaction_before_any_model_call",
      "test_resilience_security.py::test_prompt_injection_in_email_cannot_create_claims_or_actions", "test_resilience_security.py::test_nl_query_is_not_sql"]),
    # ---------------------------------------------------------------- phishing
    ("Phishing", "Ingestion of reported mail with original headers (replay-safe)", ["test_phishing.py::test_reported_message_ingested_with_original_headers"]),
    ("Phishing", "Decomposition incl. QR codes; BEC detection", ["test_phishing.py::test_qr_code_is_decoded_and_bec_detected"]),
    ("Phishing", "Verdicts on the labelled corpus", ["test_phishing.py::test_corpus_verdicts"]),
    ("Phishing", "Full investigation: reconciliation, campaign scope, clicks, endpoint + identity impact",
     ["test_phishing.py::test_full_investigation_of_reported_campaign"]),
    ("Phishing", "Explainable verdict (counterfactual, cited claims)", ["test_feature_checks.py::test_phishing_verdict_is_explained_with_counterfactual_and_citations"]),
    ("Phishing", "Remediation gated and VIP-aware; sender block via Exchange admin API",
     ["test_phishing.py::test_remediation_recommendations_are_gated_and_vip_aware", "test_feature_checks.py::test_block_sender_goes_through_the_exchange_admin_api",
      "test_connectors.py::test_exchange_admin_calls_use_their_own_token_audience"]),
    ("Phishing", "Auto-close with QA sampling", ["test_phishing.py::test_auto_close_with_sampling"]),
    ("Phishing", "Indicator propagation to the shared store", ["test_phishing.py::test_confirmation_propagates_indicators_to_shared_store"]),
    ("Phishing", "Metrics and audit", ["test_phishing.py::test_metrics_and_audit"]),
    ("Phishing", "Supplier / vendor email risk (U18)", ["test_phishing.py::test_supplier_email_risk_u18"]),
    # ---------------------------------------------------------------- incident
    ("Incident", "Alerts from many tools cluster into one incident; noise suppressed",
     ["test_incident.py::test_alerts_from_many_tools_cluster_into_one_incident", "test_incident.py::test_noisy_detection_is_suppressed"]),
    ("Incident", "Consolidated context from parallel enrichment; partial results named",
     ["test_incident.py::test_investigation_builds_consolidated_context", "test_resilience_security.py::test_investigation_completes_and_names_unavailable_sources"]),
    ("Incident", "Ranked, gated recommendations; reversible containment; read-only forensics",
     ["test_incident.py::test_recommendations_are_ranked_gated_and_well_formed", "test_feature_checks.py::test_incident_recommends_reversible_containment_and_read_only_forensics"]),
    ("Incident", "Lead approval reaches the EDR (multi-vendor routing)",
     ["test_incident.py::test_lead_approves_isolation_and_it_reaches_the_edr", "test_connectors.py::test_actions_registry_routes_endpoint_isolation"]),
    ("Incident", "Dispositions, similar incidents, shift handover, detection tuning", ["test_incident.py::test_disposition_similar_incidents_handover_and_quality"]),
    ("Incident", "Replayed alerts do not duplicate; webhook ingestion", ["test_resilience_security.py::test_replayed_alerts_do_not_duplicate", "test_api.py::test_siem_push_and_ui"]),
    # ---------------------------------------------------------------- vulnerability
    ("Vulnerability", "Four scanners consolidate to one record per asset × CVE", ["test_vulnerability.py::test_four_scanners_consolidate_to_one_record_per_asset_and_cve"]),
    ("Vulnerability", "Prioritisation beyond CVSS (EPSS, KEV, exposure, criticality)", ["test_vulnerability.py::test_prioritisation_goes_beyond_cvss"]),
    ("Vulnerability", "Affected devices with owner and provenance", ["test_vulnerability.py::test_affected_devices_have_owner_and_provenance"]),
    ("Vulnerability", "Campaigns: notifications wait for approval, plans tracked, follow-ups",
     ["test_vulnerability.py::test_campaign_notifications_wait_for_approval_then_track", "test_vulnerability.py::test_ticket_channel_when_no_contact"]),
    ("Vulnerability", "Validation detects false closures; two-way ITSM sync reopens tickets",
     ["test_vulnerability.py::test_validation_detects_false_closure", "test_vulnerability.py::test_itsm_bidirectional_sync_detects_false_closure"]),
    ("Vulnerability", "Exceptions (separation of duties, expiry) and risk register",
     ["test_vulnerability.py::test_exception_separation_of_duties_and_expiry", "test_vulnerability.py::test_risk_register_proposals_need_lead"]),
    ("Vulnerability", "Metrics computed in code; natural-language query shows its filter",
     ["test_vulnerability.py::test_metrics_are_computed_not_generated", "test_vulnerability.py::test_natural_language_query_shows_generated_filter"]),
    ("Vulnerability", "New KEV exposure assessment; coverage and data quality",
     ["test_vulnerability.py::test_new_kev_addition_exposure_assessment", "test_vulnerability.py::test_coverage_and_data_quality"]),
    ("Vulnerability", "Cloud misconfiguration lifecycle (U03)", ["test_vulnerability.py::test_cloud_misconfiguration_lifecycle_u03"]),
    ("Vulnerability", "Everything audited", ["test_vulnerability.py::test_everything_is_audited"]),
    # ---------------------------------------------------------------- intelligence
    ("Intelligence", "Explainable entity risk", ["test_intelligence.py::test_entity_risk_is_explainable_and_ranked"]),
    ("Intelligence", "Cross-domain correlation rules; dismissed insights stay dismissed unless worse",
     ["test_intelligence.py::test_cross_domain_correlations", "test_intelligence.py::test_dismissed_insight_stays_dismissed_unless_worse"]),
    ("Intelligence", "Analyst assistant (deterministic and LLM planners, catalogue-only tools, grounded)",
     ["test_intelligence.py::test_ask_without_llm_uses_deterministic_planner", "test_intelligence.py::test_ask_with_llm_plans_only_catalogue_tools_and_is_grounded",
      "test_api.py::test_intelligence_endpoints"]),
    ("Intelligence", "Situation brief across all domains", ["test_intelligence.py::test_brief_covers_all_domains"]),
    ("Intelligence", "LLM providers: Azure OpenAI / Anthropic / OpenAI-compatible",
     ["test_intelligence.py::test_provider_factory", "test_intelligence.py::test_anthropic_provider", "test_intelligence.py::test_openai_compatible_provider"]),
    ("Intelligence", "ATT&CK coverage (U09)", ["test_feature_checks.py::test_attack_coverage_reflects_enabled_tools_and_observed_alerts"]),
    ("Intelligence", "Shadow IT (U11)", ["test_feature_checks.py::test_shadow_it_classifies_services_and_risky_destinations"]),
    ("Intelligence", "Drift monitoring (R14)", ["test_intelligence.py::test_drift_monitor_flags_agreement_drop_and_verdict_shift"]),
    # ---------------------------------------------------------------- connectors
    ("Connectors", "All 20 connectors discovered; every stream syncs; every lookup answers",
     ["test_connectors.py::test_every_tool_in_the_requirements_has_a_connector", "test_connectors.py::test_all_streams_sync_into_context_store",
      "test_connectors.py::test_lookups", "test_connectors.py::test_registry_status_lists_everything"]),
    ("Connectors", "Health probes and Test endpoint (failures reported without leaking secrets)",
     ["test_connectors.py::test_every_connector_health_probe_passes_in_fixture_mode", "test_connectors.py::test_health_probe_reports_failure_without_leaking_secrets"]),
    ("Connectors", "Vendor API specifics: MDE timestamp, Rapid7/Wiz CVE lookups, Wiz pagination, Jira page tokens",
     ["test_connectors.py::test_mde_findbyip_sends_a_timestamp", "test_connectors.py::test_rapid7_and_wiz_cve_lookups_return_affected_assets",
      "test_connectors.py::test_wiz_lookup_follows_pagination", "test_connectors.py::test_jira_uses_enhanced_search_with_page_tokens"]),
    ("Connectors", "Resilience: rate limits retried, malformed records isolated, checkpoints and reconciliation",
     ["test_core_context.py::test_backoff_retries_rate_limits", "test_resilience_security.py::test_rate_limit_then_success_is_retried",
      "test_resilience_security.py::test_malformed_vendor_record_does_not_stop_the_stream", "test_core_context.py::test_sync_checkpoints_reconciles_and_isolates_bad_records",
      "test_connectors.py::test_lookup_failure_is_reported_not_raised"]),
    ("Connectors", "Configuration: secrets interpolation, missing live config reported, threat-intel attribution",
     ["test_connectors.py::test_secret_interpolation", "test_connectors.py::test_live_mode_reports_missing_config",
      "test_connectors.py::test_threat_intel_fusion_attributes_every_source"]),
    ("LLM (live)", "Configured LLM endpoint answers on the pinned model; grounded answers cited, identities redacted, calls logged - opt-in (--llm)",
     ["test_live_llm.py::test_provider_round_trip", "test_live_llm.py::test_grounded_answer_is_cited_redacted_and_logged",
      "test_live_llm.py::test_every_llm_call_succeeded_on_the_pinned_model"]),
    ("LLM (live)", "Live LLM writes incident summaries, phishing explanations and analyst answers, all cited - opt-in (--llm)",
     ["test_live_llm.py::test_incident_summaries_written_by_llm_and_cited", "test_live_llm.py::test_phishing_explanation_written_by_llm_and_redacted",
      "test_live_llm.py::test_analyst_answers_with_llm"]),
    ("LLM (live)", "Live LLM deep analysis bound to the story, and all standard reports + prompt planner - opt-in (--llm)",
     ["test_live_llm.py::test_deep_analysis_on_the_sample_estate", "test_live_llm.py::test_every_standard_report_with_llm_narrative"]),
    ("Connectors", "Live public feeds (NVD, EPSS, CISA KEV) - network, opt-in",
     ["test_live_public_feeds.py::test_nvd_detail", "test_live_public_feeds.py::test_epss_scores", "test_live_public_feeds.py::test_cisa_kev_catalogue"]),
    # ---------------------------------------------------------------- operations
    ("Operations", "Durable jobs: retries, dead letter + alert, leases, end-to-end job bodies",
     ["test_jobs.py::test_transient_failure_is_retried_and_recorded", "test_jobs.py::test_repeated_failures_dead_letter_raise_insight_and_recover",
      "test_jobs.py::test_lease_prevents_two_replicas_running_the_same_job", "test_jobs.py::test_every_scheduled_job_runs_end_to_end_on_fixtures"]),
    ("Operations", "Reports (daily, weekly, deck, investigation) and compliance pack; pack detects violations",
     ["test_api.py::test_reports_and_audit_chain", "test_demo_walkthrough.py::test_full_client_demo",
      "test_feature_checks.py::test_compliance_pack_fails_when_a_control_is_violated"]),
    # ---------------------------------------------------------------- attack story, deep analysis, report builder
    ("Attack story", "Cross-tool attack chain: ATT&CK stages, blocked steps, gaps checked, benign explanations tested, blast radius, phased plan",
     ["test_story.py::test_story_reconstructs_the_cross_tool_chain", "test_story.py::test_clean_email_produces_no_attack_story"]),
    ("Attack story", "Never invents evidence: every step is a stored record; same story from any case about the same attack",
     ["test_story.py::test_story_never_invents_evidence"]),
    ("Attack story", "Bundle approval keeps governance (four-eyes, per-action policy); analyst chat tells the story",
     ["test_story.py::test_story_over_http_bundle_approval_keeps_governance", "test_story.py::test_analyst_tells_the_story"]),
    ("Attack story", "Deep LLM analysis bound to evidence: uncited/invented statements and fake actions dropped, identities pseudonymised, cached, budgeted",
     ["test_story.py::test_deep_analysis_is_bound_to_evidence", "test_story.py::test_deep_analysis_respects_the_token_budget"]),
    ("Reports", "Report builder: 7 standard reports build from computed figures (Word / PowerPoint)",
     ["test_report_builder.py::test_every_standard_report_builds_from_computed_figures"]),
    ("Reports", "Reports described in words: planner uses catalogue sources only (LLM or keyword rules)",
     ["test_report_builder.py::test_prompt_planner_only_uses_catalogue_sources"]),
    ("Reports", "LLM narrative grounded on figures: invented figures and uncited sentences removed; numbers never from the model",
     ["test_report_builder.py::test_llm_narrative_is_grounded_and_figures_never_come_from_the_model"]),
    ("Reports", "Saved templates, data-scope enforcement on build and download, reports encrypted at rest",
     ["test_report_builder.py::test_report_builder_over_http_scope_and_encryption"]),
    # ---------------------------------------------------------------- whole-system consistency
    ("Consistency", "Every figure identical on every surface: dashboards, lists, badges, brief, analyst tools, report facts, generated Word documents",
     ["test_consistency.py::test_every_figure_agrees_across_every_surface"]),
    ("Consistency", "Re-running every pipeline and scheduled job changes nothing (no duplicate cases, actions, campaigns or risk)",
     ["test_consistency.py::test_rerunning_every_pipeline_and_job_changes_nothing", "test_phishing.py::test_reported_message_ingested_with_original_headers"]),
    ("Consistency", "LLM on or off: identical verdicts, scores, severities, risk, insights, actions and findings; invented figures never shown",
     ["test_consistency.py::test_llm_on_or_off_gives_identical_figures_verdicts_and_actions",
      "test_core_context.py::test_grounded_drops_statements_with_figures_not_in_their_evidence",
      "test_core_context.py::test_figures_hidden_inside_ids_never_make_an_invented_number_look_supported"]),
    ("Consistency", "Every GET route as 7 roles: no server errors, auth required, no cross-domain leaks, explicit UTC timestamps, unknown ids 4xx",
     ["test_consistency.py::test_every_get_route_as_every_role_no_errors_no_leaks_explicit_utc"]),
    ("Consistency", "Every write route with bogus ids and malformed bodies never answers 5xx",
     ["test_consistency.py::test_malformed_input_never_crashes_any_write_route"]),
    ("Consistency", "Every stored reference resolves (links, evidence, actions, campaigns, insights, citations)",
     ["test_consistency.py::test_every_stored_reference_resolves"]),
    ("Consistency", "Platform self-check in product: hourly job + endpoint; catches corruption, raises and resolves a finding",
     ["test_consistency.py::test_self_check_passes_on_a_consistent_platform_and_catches_corruption",
      "test_consistency.py::test_self_check_endpoint_is_for_all_domain_auditors"]),
    # ---------------------------------------------------------------- resilience and cost
    ("Resilience", "LLM endpoint slow or down: bounded timeout, one retry on throttling, circuit breaker with instant deterministic fallback",
     ["test_intelligence.py::test_failing_model_endpoint_trips_the_breaker_and_screens_fall_back_instantly",
      "test_intelligence.py::test_throttled_model_call_is_retried_once"]),
    ("Resilience", "Token budget findings at 80 % / 100 %; self-check alerts only on checks that fail twice; stopped scheduler reported",
     ["test_consistency.py::test_budget_alert_and_confirmed_self_check_alerts", "test_api.py::test_health_reports_a_stopped_scheduler"]),
    ("Resilience", "Scale: ranking and correlation profile only users/hosts with a risk source (same results, orders of magnitude faster)",
     ["test_intelligence.py::test_risk_ranking_only_profiles_entities_with_risk_sources"]),
    ("Cost", "Brief reused while its facts are unchanged; auto-closed reports spend no tokens; routine narrative on the small tier",
     ["test_intelligence.py::test_brief_is_reused_while_its_facts_are_unchanged",
      "test_phishing.py::test_auto_closed_reports_do_not_spend_llm_tokens"]),
    # ---------------------------------------------------------------- generalisation
    ("Generalisation", "Whole platform on a renamed organisation (other domain, people, hosts, IPs, suppliers): identical results",
     ["test_generalisation.py::test_renamed_estate_gives_structurally_identical_results",
      "test_generalisation.py::test_every_feature_produced_real_output_on_the_new_organisation"]),
    ("Generalisation", "No sample-estate names leak into outputs about the new organisation (stories, insights, answers, reports)",
     ["test_generalisation.py::test_no_original_names_leak_into_the_new_organisation"]),
    ("Generalisation", "Seeded variant estates (other organisations, people, machines, volumes) really differ and every feature follows the data",
     ["test_variants.py::test_variants_really_differ_from_the_built_in_estate", "test_variants.py::test_attack_story_follows_the_data",
      "test_variants.py::test_vulnerability_coverage_tracks_the_generated_gaps"]),
    ("Generalisation", "Phishing verdicts match labels on every estate's corpus; reports and answers never mention another estate",
     ["test_variants.py::test_phishing_verdicts_match_labels_on_every_corpus",
      "test_variants.py::test_reports_and_answers_never_mention_another_estate"]),
]

NOT_AUTOMATED = [
    ("Vendor connectors against the client's real tenants", ("Each connector is built to the vendor's documented API and exercised on vendor-shaped "
     "fixtures through the same code. Real tenants need credentials: press *Test* per connector (Integrations screen).")),
    ("Other LLM providers with real keys (Azure OpenAI deployments API, Anthropic, self-hosted)", ("Azure AI Foundry is verified live "
     "with `--llm`; the other adapters are tested against the official request shapes with stubbed responses.")),
    ("Detonation on an isolated sandbox host / CAPEv2", ("Hardening and fail-closed behaviour are unit-tested in the engine suite; "
     "actual detonation needs the isolated host.")),
    ("Entra ID SSO login flow", "RS256/JWKS validation is tested with signed tokens; the browser SSO redirect needs an app registration."),
    ("Docker Compose deployment", "Compose file validated (YAML/services); images were not built in this environment."),
    ("Accuracy and latency on client data / volumes", "Measured on synthetic and public data only; shadow-mode metrics measure it in production."),
]


def run_pytest(tests: list[str], extra_env: dict[str, str] | None = None) -> dict[str, str]:
    xml = Path(tempfile.mkdtemp()) / "results.xml"
    ids = sorted({T + t for t in tests})
    env = {**os.environ, **(extra_env or {})}
    subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", f"--junitxml={xml}", *ids],
                   cwd=ROOT, env=env, check=False)
    res: dict[str, list[str]] = defaultdict(list)
    for tc in ET.parse(xml).getroot().iter("testcase"):  # nosec B314 - our own pytest junit output, local temp file
        cls, name = tc.get("classname", ""), tc.get("name", "").split("[")[0]
        key = cls.replace("soc_platform.tests.", "").split(".")[0] + ".py::" + name
        outcome = "fail" if tc.find("failure") is not None or tc.find("error") is not None else \
            "skip" if tc.find("skipped") is not None else "pass"
        res[key].append(outcome)
    return {k: ("fail" if "fail" in v else "skip" if all(o == "skip" for o in v) else "pass") for k, v in res.items()}


def run_evaluations() -> list[tuple[str, str, bool]]:
    out = []
    py = sys.executable

    def js(cmd):
        p = subprocess.run([py, *cmd], cwd=ROOT, capture_output=True, text=True, check=False,
                           env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        txt = p.stdout[p.stdout.find("{"):]
        return json.loads(txt)
    e = js(["scripts/eval_phishing.py"])["heuristic"]
    out.append(("Labelled phishing corpus", f"{e['labelled']} messages, detection {e['detection_rate']:.0%}, false positives {e['false_positive_rate']:.0%}",
                e["detection_rate"] == 1.0 and e["false_positive_rate"] == 0.0))
    i = js(["scripts/eval_identity_resolution.py", "300", "5"])
    out.append(("Identity resolution stress test (300 people)", f"false merges {i['false_merges']}, split rate {i['split_rate']:.1%}, phantom built-ins {i['phantom_builtin_identities']}",
                i["false_merges"] == 0 and i["split_rate"] <= 0.02 and i["phantom_builtin_identities"] == 0))
    a = js(["scripts/eval_resolution_at_scale.py", "400", "7"])
    out.append(("Asset resolution stress test (400 hosts)", f"false merges {a['false_merges']}, split rate {a['split_rate']:.1%}, unresolved {a['unresolved_rate']:.1%}",
                a["false_merges"] == 0))
    return out


def llm_env() -> dict[str, str]:
    """SOC_LLM_* from the environment, else from the repository's .env (values never printed)."""
    env = {k: v for k, v in os.environ.items() if k.startswith("SOC_LLM_")}
    if "SOC_LLM_PROVIDER" not in env and (ROOT / ".env").is_file():
        for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
            k, sep, v = line.partition("=")
            if sep and k.strip().startswith("SOC_LLM_"):
                env[k.strip()] = v.split(" #")[0].strip()
    return env


def run_browser_tour(with_llm: bool = False, shots: Path | None = None) -> tuple[bool, str]:
    """Tour into a temporary folder (docs/screenshots is only refreshed deliberately, via SOC_SHOTS)."""
    tour = ROOT / "scripts" / "ui_tour"
    if not (tour / "node_modules" / "axe-core").exists():
        npm = shutil.which("npm") or shutil.which("npm.cmd")
        if npm is None:
            raise RuntimeError("npm is required for the browser tour")
        subprocess.run([npm, "install", "--silent", "--no-audit", "--no-fund"], cwd=tour, check=True)  # nosec B603 - fixed argv
    tmp = Path(tempfile.mkdtemp())
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    env = {**os.environ, "SOC_AUTH_MODE": "dev", "SOC_DEV_JWT_SECRET": "verify-" + os.urandom(16).hex(), "SOC_ENVIRONMENT": "dev",
           "SOC_DATABASE_URL": f"sqlite:///{tmp / 'soc.db'}", "SOC_ORG_DOMAINS": "acme-demo.com",
           "SOC_REPORT_OUTPUT_DIR": str(tmp / "reports"), "SOC_RAW_PAYLOAD_DIR": str(tmp / "raw"),
           **(llm_env() if with_llm else {"SOC_LLM_PROVIDER": "none"})}
    shots = shots or tmp / "shots"
    server = subprocess.Popen([sys.executable, "-m", "uvicorn", "soc_platform.api.app:app", "--host", "127.0.0.1", "--port", str(port)],
                              cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(60):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2)  # nosec B310 - fixed local http URL
                break
            except OSError:
                time.sleep(1)
        p = subprocess.run(["node", "tour.js"], cwd=tour, env={**os.environ, "SOC_BASE": f"http://127.0.0.1:{port}", "SOC_SHOTS": str(shots)},
                           capture_output=True, text=True, check=False)
        res = json.loads((shots / "tour-result.json").read_text())
        ok = p.returncode == 0 and not res["problems"]
        detail = (("LLM on - " if with_llm else "") + f"{res['screenshots']} screenshots, layout audited at {', '.join(map(str, res['audited_widths']))} px in light + dark, "
                  "every KPI / badge / tab count on screen cross-checked against the API; "
                  f"problems: {len(res['problems'])}" + ("" if ok else " - " + "; ".join(res["problems"][:5])))
        return ok, detail
    finally:
        server.terminate()
        server.wait(timeout=20)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--browser", action="store_true")
    ap.add_argument("--engine", action="store_true")
    ap.add_argument("--live", action="store_true", help="also run the live public-feed tests (network)")
    ap.add_argument("--llm", action="store_true", help="also run the live LLM tests and the browser tour with the configured LLM (costs tokens)")
    args = ap.parse_args()
    started = datetime.now(UTC)
    tests = sorted({t for _, _, ts in FEATURES for t in ts})
    results = run_pytest(tests, {**({"SOC_LIVE_TESTS": "1"} if args.live else {}), **({"SOC_LIVE_LLM": "1"} if args.llm else {})})
    missing = [t for t in tests if t not in results]
    evals = run_evaluations()
    browser = run_browser_tour(with_llm=args.llm) if args.browser else None
    engine = None
    if args.engine:
        p = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "soc_platform/domains/phishing/tests/unit"],
                           cwd=ROOT, capture_output=True, text=True, check=False)
        engine = (p.returncode == 0, (p.stdout.strip().splitlines() or ["no output"])[-1])

    rows, counts = [], defaultdict(int)
    for area, feat, ts in FEATURES:
        outs = [results.get(t, "missing") for t in ts]
        status = ("FAILED" if "fail" in outs or "missing" in outs else
                  "not run (opt-in)" if all(o == "skip" for o in outs) else "VERIFIED")
        counts[status] += 1
        ev = "<br>".join(f"{'✅' if results.get(t) == 'pass' else '⏭️' if results.get(t) == 'skip' else '❌'} `{t}`" for t in ts)
        rows.append((area, feat, status, ev))

    md = ["# Feature verification", "",
          (f"Generated by `python scripts/verify_features.py{' --browser' if args.browser else ''}{' --engine' if args.engine else ''}{' --live' if args.live else ''}{' --llm' if args.llm else ''}` "
          f"on {started:%Y-%m-%d %H:%M} UTC. Re-run it any time; every row names the tests that prove it."), "",
          "## Summary", "", "| Check | Result |", "|---|---|",
          f"| Features verified by automated tests | **{counts['VERIFIED']} of {len(FEATURES)}**"
          + (f" ({counts['FAILED']} failed)" if counts["FAILED"] else "")
          + (f" · {counts['not run (opt-in)']} opt-in (network / LLM) not run" if counts["not run (opt-in)"] else "") + " |",
          (f"| Tests mapped to features, executed | {sum(1 for v in results.values() if v != 'skip')} run, "
          f"{sum(1 for v in results.values() if v == 'fail')} failed |")]
    for name, detail, ok in evals:
        md.append(f"| {name} | {'✅' if ok else '❌'} {detail} |")
    if browser:
        md.append(f"| Browser tour (real server + browser, every screen, 4 roles) | {'✅' if browser[0] else '❌'} {browser[1]} |")
    if engine:
        md.append(f"| Phishing ML engine suite | {'✅' if engine[0] else '❌'} {engine[1]} |")
    if missing:
        md.append(f"| Mapped tests not found | ❌ {', '.join(missing)} |")
    area = None
    for a, feat, status, ev in rows:
        if a != area:
            md += ["", f"## {a}", "", "| Feature | Status | Evidence (tests) |", "|---|---|---|"]
            area = a
        md.append(f"| {feat} | {'✅ ' if status == 'VERIFIED' else '❌ ' if status == 'FAILED' else '⏭️ '}{status} | {ev} |")
    md += ["", "## What automated verification cannot prove", "",
           "These need the client's environment or credentials; the platform is built for them but they have not been exercised here.", "",
           "| Item | Status |", "|---|---|"] + [f"| {a} | {b} |" for a, b in NOT_AUTOMATED]
    OUT.write_text("\n".join(md) + "\n", encoding="utf-8")
    ok = counts["FAILED"] == 0 and all(e[2] for e in evals) and (browser is None or browser[0]) and (engine is None or engine[0]) and not missing
    print(f"{counts['VERIFIED']}/{len(FEATURES)} features verified; evaluations {'ok' if all(e[2] for e in evals) else 'FAILED'}"
          + (f"; browser {'ok' if browser[0] else 'FAILED'}" if browser else "") + f" -> {OUT}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
