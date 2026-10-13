# Data handoff reconciliation

How the platform lines up with the organisation's **security tool data types handoff workbook** (final engineering
handoff: tool inventory, synthetic payloads, field dictionary, correlation mapping, entity catalog, acceptance scenarios,
generation rules, connector scope). The workbook itself stays outside the repository (it is gitignored); this document
is the engineering answer to it, sheet by sheet.

The workbook says its payloads are **illustrative, not vendor API contracts**. The connectors therefore read each
vendor's documented API shape (for example Falcon's `composite_id`, not the workbook's `detection_id`) and map it to the
canonical record; the tables below give that mapping. Validation against the organisation's own tenants is the pilot.

**Status words.** *Aligned* - the data type is read and its fields are used. *Aligned (on demand)* - queried during an
investigation for the hosts, people and indicators of a case, not bulk-ingested (event-level telemetry would be large).
*Platform-owned* - the state the row describes is kept by the platform's own workflow (SLA, exception, approval).
*Partial* - read, with the named field(s) not available or not taken. *Not taken* - not read, with the reason.

## 1. Connector scope (sheet "Connector Scope Reconcile")

The workbook counts **13 commercial tool families** and **21 integration rows**. The platform has **21 connectors**:
one per tool family (Delinea counts as two products, as in the workbook) and 8 feeds / interfaces.

| Workbook row | Connector | Notes |
|---|---|---|
| CrowdStrike Falcon | `crowdstrike` | alerts, hosts, Spotlight vulnerabilities |
| Microsoft Defender for Endpoint | `defender_endpoint` | alerts, machines, TVM vulnerabilities; advanced hunting on demand |
| Microsoft Defender for Identity | `defender_identity` | alerts, domain logon events (added for this handoff) |
| Microsoft Defender for Office 365 | `defender_office365` | reported messages, e-mail alerts; EmailEvents / UrlClickEvents / ... on demand |
| Microsoft Entra ID | `entra` | users, sign-ins, risky users, risk detections, directory audits |
| Avanan / Harmony Email | `avanan` | security events, per-message verdict by InternetMessageId |
| Rapid7 InsightVM | `rapid7` | assets, findings, vulnerability exceptions (exceptions added for this handoff) |
| Wiz | `wiz` | resources, vulnerability findings, issues (misconfigurations) |
| Cisco Umbrella | `umbrella` | DNS activity |
| Delinea Secret Server | `delinea_secret_server` | secret audits |
| Delinea Privilege Manager | `delinea_privilege_manager` | elevation events |
| Thinkst Canary | `canary` | incidents, devices |
| ServiceNow | `servicenow` | tickets, CMDB |
| NVD | `nvd` | CVE metadata |
| EPSS | `epss` | exploit probability |
| CISA KEV | `cisa_kev` | known exploited vulnerabilities |
| Threat intelligence fusion | `threat_intel` | 8 sources, each opt-in; internal indicators never sent out |
| Jira | `jira` | alternative to ServiceNow |
| Ownership CSV | `cmdb_csv` | fallback ownership source |
| Microsoft Sentinel | `sentinel` | incidents and their entities |
| Generic SIEM push | `generic_siem` | **inbound**: a SIEM / SOAR pushes alerts to `POST /api/v1/ingest/alerts`. The workbook describes this row as an *outbound* interface; the platform's outbound deliveries are the Teams / Slack / JSON webhook notifications (`SOC_NOTIFY_WEBHOOKS`) and the audit / log export. The row should be corrected in the workbook. |

## 2. Data types and fields (sheets "Final JSON Payloads", "Final Field Dictionary")

All 38 payload rows. Field names on the right are the vendor fields the connector reads.

| Tool / event type | Platform source | Status | Field mapping and notes |
|---|---|---|---|
| CrowdStrike `endpoint_detection` | `crowdstrike.alerts` (Alerts API v2) | Aligned | detection_id → `composite_id`; device_id → `device.device_id` (device key); hostname, local_ip → `device.*`; username → `user_name`; process_name → `filename`; sha256; severity → severity name; timestamp → `created_timestamp`; parentProcess → `parent_details.cmdline`; containment → host `status` (hosts stream) |
| CrowdStrike `host_inventory` | `crowdstrike.hosts` | Aligned | device_id, hostname, local_ip, platform / OS, last_seen; serial and MAC as keys |
| CrowdStrike `contradictory_alert` | `crowdstrike.alerts` | Aligned | status / tags (closed, false positive) → `source_verdict`; the incident flags the disagreement (section 5, EDGE-01) |
| Defender for Endpoint `endpoint_alert` | `defender_endpoint.alerts` | Aligned | AlertId → `id`; DeviceId → `machineId`; DeviceName → `computerDnsName`; AccountUpn → `relatedUser`; FileName / SHA256 / RemoteIP → `evidence` (IP evidence added for this handoff); incidentId, severity, title, status; classification / determination → `source_verdict` |
| Defender for Endpoint `device_network_event`, `device_process_event`, `device_file_event` | advanced hunting (`DeviceNetworkEvents`, `DeviceProcessEvents`, `DeviceFileEvents`) | Aligned (on demand) | queried for a case's host and indicators during enrichment |
| Defender for Endpoint `duplicate_network_event` | ingestion | Aligned | a replayed record is ignored by its source id; every pipeline is run twice in tests and changes nothing |
| Defender for Identity `identity_alert` | `defender_identity.alerts` (Graph alerts_v2) | Aligned | AlertId → `id`; AccountSid → `userEvidence.userAccount.userSid`; AccountUpn → `userPrincipalName`; DeviceName → `deviceEvidence.deviceDnsName`; IPAddress → `ipEvidence`; Timestamp → `createdDateTime` |
| Defender for Identity `identity_logon_event` | `defender_identity.logon_events` (`IdentityLogonEvents`) | Aligned | Timestamp, AccountSid, AccountUpn, DeviceName, DomainController → `DestinationDeviceName`, ActionType, LogonType, Protocol, IPAddress, FailureReason; evidence only, raises no risk on its own |
| Entra `signin_log` | `entra.signins` | Partial | id, userId, userPrincipalName, ipAddress, appId, correlationId, createdDateTime, status.errorCode, riskLevelDuringSignIn, conditionalAccessStatus, appDisplayName, authenticationRequirement. `mfaResult` is not a Graph v1.0 sign-in field (per-method MFA detail is beta-only) and is not read |
| Entra `audit_event` | `entra.directory_audits` | Aligned | id, activityDisplayName, initiatedBy.user, targetResources, activityDateTime, category, result |
| Entra `consent_audit_event` | `entra.directory_audits` | Aligned | "Consent to application" recorded with the application(s) and correlationId; rule `consent_after_phishing` (section 5, PHISH-02) |
| Entra `benign_signin` | `entra.signins` | Aligned | informational, no risk factor |
| Wiz `cloud_finding` | `wiz.vulnerabilities` (+ `wiz.resources`) | Aligned | findingId → `id`; resourceId → vulnerable asset id; cve; severity / score; publicExposure → `hasWideInternetExposure`; detectedAt → `firstDetectedAt`; fixedVersion; resource name, type, region and cloud account from the resource record |
| Wiz `misconfiguration_finding` | `wiz.issues` | Aligned | findingId, resourceId, resource name / type, cloud, region, ruleId → `sourceRule.id` (added), rule name, severity, status |
| Rapid7 `vulnerability_finding` | `rapid7.findings` (+ `rapid7.assets`) | Aligned | assetId, hostname, ip, vulnerabilityId, cve, cvssV3Score, severity, status, firstFound → `since`; riskScore and lastScan from the asset. slaDue, exceptionStatus, remediationTicket are platform-owned (below) |
| Rapid7 `scan_status` | - | Not taken | scan runs are not read; fix validation re-queries the asset, and a finding disappears only after a scan that no longer sees it (VM-01) |
| Rapid7 `vulnerability_remediation` | vulnerability workflow | Platform-owned | finding age, priority band, SLA due date, owner, remediation ticket, exception, verification |
| Rapid7 `vulnerability_rescan` | fix validation (`verify_finding`) | Aligned | still present / not present / asset missing per scanner; closed only on "not present" |
| Rapid7 `risk_exception` | `rapid7.exceptions` (added) | Aligned | state, expiry, reason, comments shown on the finding with "in force" / "expired"; never closes or suppresses it - exceptions the platform honours are approved in the platform (four-eyes, expiry) |
| Umbrella `dns_event` | `umbrella.dns_activity` | Partial | timestamp, domain, sourceIp → `internalip`, identity, action → `verdict`, categories, queryType, responseCode → `returncode` (added), user. The DNS activity report carries no policy name; the categories that triggered the policy are kept |
| Umbrella `benign_dns_event` | `umbrella.dns_activity` | Aligned | allowed, non-security category: no risk, no story |
| Delinea Secret Server `secret_audit`, `secret_checkout` | `delinea_secret_server.secret_audits` | Partial | auditId, secretId, secretName, user, action, sourceIp, machine, timestamp, notes (a ticket reference is recorded there when the ticket system is enforced); humanOwner → approved `account_owners` map (added). checkoutExpiry is not in the audit record |
| Delinea Privilege Manager `elevation_event`, `elevation_decision` | `delinea_privilege_manager.elevation_events` | Partial | eventId, timestamp, deviceName, user, fileName, fileHash, policyName, action → `outcome`, justification. policyId and approvedBy are not taken |
| Thinkst Canary `canary_alert` | `canary.incidents` | Aligned | alertId, canaryId → `node_id`, sourceIp → `src_host`, timestamp, canaryName, logtype, description, acknowledged; the source host is resolved by IP at event time and never merged on the IP alone |
| Defender for Office 365 `email_threat` | `EmailEvents` on demand + `defender_office365.email_alerts` | Aligned | NetworkMessageId, InternetMessageId, SenderFromAddress, RecipientEmailAddress, ThreatTypes, DeliveryAction, DeliveryLocation, Subject, DetectionMethods |
| Defender for Office 365 `url_click` | `UrlClickEvents` on demand | Aligned | `ClickAllowed` or `IsClickedThrough` = a click; `ClickBlocked` = blocked, never a click-through (PHISH-01 negative) |
| Defender for Office 365 `email_url_info`, `email_attachment_info` | `EmailUrlInfo`, `EmailAttachmentInfo` on demand | Aligned | campaign scope by URL domain and attachment hash |
| Defender for Office 365 `post_delivery_action` | `EmailPostDeliveryEvents` on demand; action requests | Aligned / platform-owned | what the tenant did after delivery is read; "recommended, not executed, approval required" is the platform's own action-request state |
| Avanan `email_verdict` | `avanan.security_events`; verdict by InternetMessageId | Aligned | messageId → `eventId` / `entityId`; sender; recipients; subject; verdict; action; timestamp; internetMessageId |
| ServiceNow `incident_record` | `servicenow.tickets` | Aligned | sys_id, number, short_description, priority, state, assignment_group, cmdb_ci, opened_at, resolved_at, assigned_to, correlation_id (priority onwards added); tickets the platform opens carry the vendor alert ids (sourceAlertIds) |
| ServiceNow `cmdb_asset` | `servicenow.cmdb` | Aligned | sys_id, name, ip_address, owned_by, business_criticality, support group, environment, location; serial and MAC as keys |
| ServiceNow `incident_history` | `servicenow.tickets`, status checks | Partial | the current state is read every sync and each change the platform sees is audited; the instance's own state history (sys_audit) is not read |
| ServiceNow `remediation_task` | remediation tickets (`ticket_table` setting) | Aligned | parent (added), state, closure; a ticket closed while a scanner still sees the CVE is a false closure and reopens |

## 3. Correlation rules (sheet "Correlation Mapping")

| Workbook rule | Platform behaviour | Test |
|---|---|---|
| CrowdStrike device_id vs MDE DeviceId: not equivalent; host name + inventory + time; ambiguous to review | separate keys per tool; joined on a unique exact name **and** the same address inside the IP window (3 days) and the same OS family (auto threshold 0.85); a name alone scores 0.75 and goes to review | `test_handoff_scenarios.py::test_a_device_seen_by_two_tools_joins_on_name_plus_address_at_the_same_time`, `::test_a_name_alone_never_joins_two_devices_it_goes_to_review` |
| Rapid7 asset vs CrowdStrike: never IP-only | an IP-only record is never merged (review queue); an IP outside its window is ignored | `test_core_context.py::test_stale_ip_is_ignored`, `test_handoff_scenarios.py::test_a_reused_ip_at_a_different_time_never_joins_two_devices` |
| Wiz resource vs CMDB / cloud id | cloud resource id is a cross-tool key; a conflicting id proves two resources | `test_core_context.py::test_conflicting_serial_prevents_merge` |
| Entra userId / UPN vs MDE / MDI AccountUpn | immutable directory object id and UPN keys; aliases from the directory | `test_identity_scale.py` |
| MDO NetworkMessageId vs Avanan messageId; join on InternetMessageId | vendor ids stay distinct; Avanan's verdict is fetched by InternetMessageId | `test_phishing.py` |
| MDO recipient vs Entra UPN | recipient address resolved through UPN / mail aliases | `test_identity_scale.py::test_alias_and_sam_seen_before_directory_collapse_into_one_person` |
| Umbrella domain / sourceIp vs MDE RemoteUrl / RemoteIP | domains and IPs are shared indicators; event time kept | `test_volume.py::test_a_dns_event_naming_a_host_with_a_namesake_links_by_its_ip_instead_of_queueing` |
| Hashes across CrowdStrike, MDE, Delinea | one SHA-256 indicator with its algorithm kept in the key (`sha256:<value>`, case-normalised), linked to every alert naming it | `test_handoff_scenarios.py::test_one_file_hash_seen_by_two_tools_is_one_indicator_linked_to_both_alerts` |
| Rapid7 vs Wiz CVE: never CVE-only | one finding per resolved asset + CVE; each scanner's record kept | `test_vulnerability.py::test_four_scanners_consolidate_to_one_record_per_asset_and_cve` |
| ServiceNow cmdb_ci vs host; no owner on a weak match | CMDB records resolve like any asset; ambiguous ones go to review | `test_core_context.py::test_ambiguous_goes_to_unresolved_queue_not_merged` |
| Canary sourceIp + time vs EDR local IP | resolved against the address at event time; never on the IP alone | `test_volume.py`, `test_core_context.py::test_stale_ip_is_ignored` |
| Secret Server admin account vs human owner | approved `account_owners` map; the admin account stays its own identity; shared accounts unmapped | `test_handoff_scenarios.py::test_an_admin_account_links_to_its_owner_only_through_the_approved_map` |
| Privilege Manager device + user vs EDR | resolved entity + event time; no name-only merge | as the device rows above |
| MDI AccountSid vs Entra | directory mapping (`onPremisesSecurityIdentifier`), not name similarity | `test_connector_defender_identity.py::test_a_person_named_only_by_sid_joins_the_entra_user_through_the_directory` |
| Umbrella identity + sourceIp vs endpoint | an event naming a host links to it (event link, never an entity merge) | `test_volume.py::test_a_dns_event_naming_a_host_with_a_namesake_links_by_its_ip_instead_of_queueing` |
| ServiceNow sourceAlertIds | platform tickets list `tool:alert id` of every alert on the case | `test_handoff_scenarios.py::test_an_incident_ticket_carries_the_original_vendor_alert_ids` |

## 4. Entity catalog (sheet "Final Entity Catalog")

Canonical ids are kept separate from vendor ids: every entity has the platform's own id, and each tool's identifier is a
separate key on it (`crowdstrike_aid`, `mde_device_id`, `rapid7_asset_id`, `wiz_id`, `cloud_resource_id`,
`entra_object_id`, `upn`, `sid`, ...). A message keeps every vendor's message id and joins on the InternetMessageId;
indicators keep their type; tickets keep their number and sys_id.

## 5. Acceptance scenarios (sheet "Acceptance Scenarios")

| Scenario | Expected | Platform | Test |
|---|---|---|---|
| PHISH-01 delivered e-mail, click, endpoint execution | correlate by InternetMessageId and person / device; recommend containment only | phishing pipeline correlates delivery, click, DNS, endpoint and identity; actions are recommended (L2); a blocked click is never a click-through | `test_phishing.py`, `test_handoff_scenarios.py::test_a_blocked_click_never_counts_as_a_click_through` |
| PHISH-02 OAuth consent after a suspicious link | flag risky consent; no compromise without corroboration | rule `consent_after_phishing` (high, "verify the application"; consent within 7 days after the click) | `test_intelligence.py::test_application_consent_after_a_phishing_click_is_flagged_for_verification` (+ 4 negative cases) |
| INC-01 EDR overlap, identity, privilege, Canary | one host / person; distinct alert ids; case with timeline and approvals | incident clustering on resolved entities; every alert kept | `test_incident.py`, `test_story.py::test_story_reconstructs_the_cross_tool_chain` |
| VM-01 exposure to verified rescan | one finding per asset + CVE; close only after rescan | consolidation + validation (`verified_remediated` only when no scanner still sees it) | `test_vulnerability.py::test_four_scanners_consolidate_to_one_record_per_asset_and_cve`, `::test_validation_detects_false_closure` |
| VM-02 exception and misconfiguration | exception expiry tracked; accepted risk is not fixed | platform exceptions (four-eyes, expiry reopens the finding); Rapid7 exceptions shown, never applied; misconfigurations share the lifecycle | `test_vulnerability.py::test_exception_separation_of_duties_and_expiry`, `test_connector_rapid7.py::test_a_scanner_exception_is_shown_on_its_finding_but_never_closes_or_suppresses_it` |
| EDGE-01 noise, conflicting verdicts, duplicate, shared IP | no false correlation; conflict flagged; no autonomous containment | tools that disagree are shown on the case and every action is held for approval; benign mail tells no story; duplicates ignored; a shared public IP merges nobody | `test_handoff_scenarios.py::test_contradicting_edr_verdicts_are_flagged_and_every_action_waits_for_a_person`, `::test_people_sharing_a_public_ip_stay_separate`, `test_story.py::test_clean_email_produces_no_attack_story` |
| EDGE-02 host name collision / DHCP reuse | never join on IP or host name alone; queue ambiguous | review queue | `test_handoff_scenarios.py::test_a_reused_name_and_address_at_a_different_time_go_to_review` |
| EDGE-03 missing fields, out-of-order, retries, partial responses | graceful; no fabricated fields | conform-to-shape, missing identifier refused with a reason, late records caught by the watermark overlap, interrupted syncs resume | `test_data_tolerance.py`, `test_connector_conformance.py::test_late_records_are_caught_by_the_overlap_and_future_times_never_move_the_mark`, `test_volume.py::test_an_interrupted_backfill_keeps_its_pages_and_resumes_after_the_last_one` |

## 6. Generation rules (sheet "Final Generation Rules")

| Rule | Platform |
|---|---|
| Fictional data only | the demo organisation is fictional (Acme, `acme-demo.com`) and variant estates are generated; the built-in fixtures use private and documentation address ranges plus a few public addresses as indicators. **Open:** the workbook asks for `example.invalid` and RFC 5737 addresses only - a workbook-conformant estate is not built yet (section 7) |
| ISO 8601 UTC canonical times; vendor formats kept raw | canonical times are aware UTC; raw payloads are stored encrypted as received; odd vendor times are read or treated as absent |
| Canonical ids separate from vendor ids | section 4 |
| Multi-key correlation, never IP / host name / CVE alone | section 3 |
| ≥ 1,000 events; 80-95 % benign | `build_estate_variant.py --messy --scale N` adds sign-in, DNS and low-severity alert volume; the benign share is not a set parameter |
| 0-15 minute ingest lag, late and out-of-order records | the watermark overlap re-reads late records (default 30 minutes) |
| Nulls, duplicate retries, inconsistent verdicts, shared IP, reused host name, API error, pagination | conformance suite (every field missing / null / wrong-typed, 429 / 401 / 403, paging and resume for every stream), section 5 |
| Ground truth per scenario | section 5 (each scenario's expected outcome is a test) |
| Phishing: a clicked message is not also blocked before the click; later actions only recommended | click logic in section 2; remediation is an action request (L2) |
| Vulnerability: age, SLA, owner, exception expiry, task, verified rescan; accepted risk is not fixed | section 5, VM-01 / VM-02 |
| Recommend-only, no live writes | default policy L2; fake mode never calls a tool |
| No production credentials or client data in development; audit approvals | `.env` gitignored, secret scans before every push, hash-chained audit of every decision |

## 7. Open items

1. **A workbook-conformant synthetic estate** (the workbook's own entity catalog: `example.invalid`, RFC 5737
   addresses, the PHISH-01 ... EDGE-03 chains, ≥ 1,000 events with a configurable benign share and 1-3 % duplicates)
   is not generated yet. The behaviour each scenario expects is tested on the built-in and generated estates.
2. **Partial fields** (section 2): Entra `mfaResult`, Umbrella policy name, Secret Server checkout expiry, Privilege
   Manager policyId / approvedBy, ServiceNow state history, Rapid7 scan runs. None is used by a workflow decision.
3. **Generic SIEM push direction**: the workbook row says outbound; the platform's is inbound (section 1).
4. **Tenant validation**: field names, licences and permissions per tool are confirmed by the tool owners in the pilot
   (`docs/client_review/06_DEPLOYMENT_AND_VALIDATION.md`).
