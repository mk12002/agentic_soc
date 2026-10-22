# High availability, scaling and disaster recovery

How the platform runs with **no single point of failure**, on premises or in the cloud, and what each failure does.
Read with `CLIENT_DEPLOYMENT_GUIDE.md` (hosting, sign-in, tools) and `OPERATIONS.md` (settings, monitoring, backups).

The short version: the application keeps **no state on a host or in a process**. Everything durable - cases, evidence,
actions, the audit chain, job leases, the kill switch, stored e-mails and reports - is in PostgreSQL. So any number of
API and scheduler replicas can run on any number of nodes, and high availability comes down to running at least two
of each and a highly available PostgreSQL.

---

## 1. Every component, its redundancy and what a failure does

| Component | Redundancy | When one instance fails | Recovery |
|---|---|---|---|
| **API** (`soc-api`) | 2+ replicas on different nodes / zones, behind a load balancer | The load balancer stops routing to it (readiness fails or the pod is gone); requests go to the others. No session is lost: sign-in tokens are checked on every request and revocations live in the database. | Kubernetes restarts or reschedules it. |
| **Scheduler** (`soc-scheduler`) | 2 replicas, each with a local liveness probe | A job the dead replica was running is **taken over within `SOC_JOB_LEASE_SECONDS` (120 s)** by the other replica; nothing runs twice. | Restarted by the orchestrator. `/health` shows `stale` if no scheduler beats for 180 s. |
| **PostgreSQL** | Managed zone-redundant HA (cloud) or a 3-instance cluster with a synchronous replica (on-prem) | The standby is promoted. Replicas check connections before use and replace broken ones; requests during the switch answer **503 + Retry-After** instead of failing, and readiness takes replicas out of the load balancer until the database answers. | Automatic failover by the service / operator. |
| **Stored files** (reported e-mails, reports; original vendor payloads with `SOC_STORE_RAW_PAYLOADS`) | In PostgreSQL (`SOC_BLOB_STORE=database`) | Covered by the database's HA: nothing to fail separately. | With the database. |
| **Ingress / WAF** | Zone-redundant Application Gateway, or 2+ ingress controller replicas behind the organisation's load-balancer pair | The other instance serves. | The service / orchestrator. |
| **A node or a zone** | Replicas are spread across nodes (and zones in the cloud); disruption budgets keep one of each during drains | The replicas on the surviving nodes serve; the lost ones are rescheduled. | Automatic. |
| **A security tool** | Not the platform's to make redundant | Investigations continue with that tool's evidence shown as unavailable; jobs, screens and reports keep working; feeds keep their last known values. | When the tool returns, the next sync resumes from its watermark. |
| **The LLM** | Optional | Explanations fall back to the deterministic, cited text; figures, verdicts and actions are identical. | Automatic (circuit breaker). |
| **Entra ID** (sign-in) | Microsoft's service | New sign-ins fail. Analysts already signed in keep working until their token expires: each process keeps the signing keys it has seen, so validation needs no call to Entra. | Break-glass access (`OPERATIONS.md` - Break-glass) for emergencies. |
| **Key Vault / secret store** | Microsoft's service / the organisation's | Running pods keep the secrets they started with; new pods cannot start until it is back. | Automatic. |

---

## 2. What the application guarantees (and the tests that prove it)

| Guarantee | How | Test |
|---|---|---|
| Any API replica serves any request | Stateless: no in-process session; tokens verified per request; caches are either keyed on database state (risk) or reloaded from it every few seconds (connector configuration) | `test_consistency.py`, `test_traffic.py` (a real multi-process server) |
| Stored files are readable by every replica | `SOC_BLOB_STORE=database`: e-mails and reports are rows in `blobs`, encrypted with `SOC_DATA_KEY`, checksummed, written in the same transaction as the record that points at them | `test_high_availability.py` (another replica re-reads an e-mail and downloads a report it did not build) |
| A job never runs twice; a dead scheduler's job is taken over quickly | A database lease (compare-and-swap) per job, **renewed every third of its length while the job runs**; a job whose scheduler died is free again one lease later. A job that runs past `SOC_SCHEDULER_STUCK_SECONDS` stops renewing, so a hung job can still be retried elsewhere | `test_high_availability.py` (renewal refuses every takeover while alive; takeover after expiry; a lost lease is reported), `test_scheduler.py`, `test_jobs.py` |
| One sync of a stream at a time, on any replica | The scheduled job, a manual sync, a refresh button and `demo` can all sync the same tool stream. A per-stream lease in the database (compare-and-swap, renewed after every page, released at the end) makes them take turns: the second waits up to `SOC_SYNC_LOCK_WAIT_SECONDS` (120) and continues from the first one's checkpoint, or reports that it skipped. A sync's first checkpoint row survives a lost insert race. Found by the Docker check: `demo` and the scheduler synced one stream together and one failed on a duplicate checkpoint | `test_high_availability.py` (two syncs at once both complete, no record twice; a held stream is waited for, then skipped; the lease is released) |
| One bad item never stops a batch | Each reported e-mail and each incident runs in its own savepoint; a failure rolls back only that item, is recorded on it (`processing_failure`, attempts), audited, logged, and retried on the next 3 runs before it is left to an analyst. A reported e-mail a stopped run left waiting is picked up by the next. | `test_jobs.py` |
| Many replicas can start at once on a fresh database | Schema creation takes a PostgreSQL advisory lock (others wait, then find nothing to do); on SQLite a lost race is retried, and switching a new file to WAL is retried while another connection holds it | `test_high_availability.py` (8 engines at once, on SQLite and PostgreSQL) |
| A database outage does not restart every pod | `/health/live` never touches the database (liveness); `/health/ready` does (readiness) | `test_high_availability.py`, `test_deployment_manifests.py` |
| A failover does not surface as errors | Connection pool with pre-ping and recycling (`SOC_DB_POOL_RECYCLE`, 1800 s); saturation or an unreachable database answers 503 + Retry-After | `test_traffic.py`, `FAILURE_MODES.md` |
| Deploys and drains never drop capacity | Rolling updates with `maxUnavailable: 0`; disruption budgets; a `preStop` pause so the load balancer stops routing before shutdown; graceful shutdown finishes requests in flight and the job in hand | `test_deployment_manifests.py` |
| Signed-in analysts keep working through an Entra outage | Signing keys already seen are kept per process; only a new key id needs Entra | `test_high_availability.py` |
| A crash between the two steps of a job loses nothing | The incident and phishing jobs commit the cases, then write the model explanations; explanations still pending are picked up by the next run | `test_incident.py` |
| A crash or failover during a tool call never re-runs or hides an action | `executing` and its audit record are committed before the tool is called, the outcome after; no transaction (or audit-chain lock) is open during the call. An action left `executing` is marked `unverified` with a finding by the actions job, never run again | `test_core_governance.py` |
| A stuck process cannot hold locks for ever | Production defaults: `statement_timeout` 300 s, `idle_in_transaction_session_timeout` 600 s | `test_go_live_hardening.py` (settings), `OPERATIONS.md` |

The PostgreSQL advisory lock is a safeguard: in testing, eight engines creating the schema at once on PostgreSQL
succeeded with and without it, because PostgreSQL's own catalogue locking usually serialises them. The SQLite start-up
race (switching a new file to WAL) was real and reproduced, and is what the retry fixes.

---

## 3. Reference deployments

Both use the same image and the same Kubernetes base (`deploy/kubernetes/base`); only the overlay differs. Choose on
cost and the organisation's operating model - the application does not change.

### 3.1 Azure (deploy/kubernetes/overlays/azure)

```
 Users --> Application Gateway (zone-redundant: the existing one, or a dedicated WAF v2 if internet-facing)
                                   |
 +--------------------+--------------------+--------------------+
 | AKS zone 1         | AKS zone 2         | AKS zone 3         |
 | soc-api            | soc-api            | soc-api            |  3 API replicas, one per zone (autoscaled to 4)
 | soc-scheduler      | soc-scheduler      |                    |  2 schedulers, different zones
 +--------------------+--------------------+--------------------+
                                   | private (VNet-integrated) access, TLS verify-full
 +--------------------------------------------------------------+
 | Azure Database for PostgreSQL Flexible Server                |
 | zone-redundant HA: synchronous standby in another            |
 | zone, automatic failover, point-in-time restore,             |
 | geo-redundant backup                                         |
 +--------------------------------------------------------------+
 Key Vault (CSI driver + workload identity) | Azure Monitor / Prometheus | the client's ACR
```

* The Azure resources themselves are code: `deploy/azure/main.bicep` (VNet with subnets for the gateway, AKS,
  PostgreSQL and private endpoints; private AKS with Entra-only sign-in, workload identity, Key Vault CSI with
  rotation, AGIC and Azure Policy; Flexible Server 16 zone-redundant with 35-day geo-redundant backup, TLS only,
  `pg_trgm` allowed; Key Vault with purge protection and no public access; ACR; every resource's logs to one Log
  Analytics workspace). SKUs follow INFRASTRUCTURE_AND_COSTS.md section 10. Internal console: AGIC drives the
  organisation's existing Application Gateway (`existingAppGatewayId`; its owner grants the AGIC identity Contributor
  on it). Internet-facing (`internetFacing=true`): a zone-redundant WAF v2 gateway in prevention mode (OWASP 3.2, bot
  rules, a per-client rate limit shared across replicas, TLS 1.2+) is created - decision D5. The template compiles
  with `az bicep build` (no warnings); run `what-if` against the subscription before the first deployment.
* Stored files: in the database (`SOC_BLOB_STORE=database`) - no storage account to make redundant.
* Disaster recovery to the paired region: geo-restore of the database (or a cross-region read replica promoted),
  the same manifests applied to a cluster there, DNS / gateway switched.

### 3.2 On premises (deploy/kubernetes/overlays/onprem)

```
 Users --> load-balancer pair (VIP) --> ingress-nginx (2+ replicas; TLS, shared rate limit)
                                   |
 +--------------------+--------------------+--------------------+
 | node 1             | node 2             | node 3             |
 | soc-api            | soc-api            |                    |  strictly one per node
 | soc-scheduler      | soc-scheduler      |                    |
 | PostgreSQL primary | sync replica       | async replica      |  CloudNativePG, one per node
 | PgBouncer          | PgBouncer          |                    |  pooler follows failovers
 +--------------------+--------------------+--------------------+
 Base backups + continuous WAL archive --> S3-compatible store (MinIO) at a second location
```

* Prerequisites: the CloudNativePG operator and ingress-nginx; a storage class for the database volumes.
* A committed transaction survives the loss of the primary (one synchronous replica); the operator promotes a
  replica and the pooler reconnects to it.

### 3.3 The smallest deployment without a single point of failure

Two virtual machines, each running the API and scheduler containers (`deploy/docker-compose.yml` without its
`postgres` service, pointed at the shared database), behind a load-balancer pair, with a managed or clustered
PostgreSQL and `SOC_BLOB_STORE=database` (the compose default). Same guarantees as section 2; capacity is
added by adding VMs. Kubernetes adds self-healing, rolling deploys and autoscaling on top.
On Azure, with two `Standard_D2s_v5` VMs in two zones and a zone-redundant PostgreSQL Flexible Server, this costs
about $554 a month on demand and $351 with 1-year reservations - the recommended size for a small SOC
(`INFRASTRUCTURE_AND_COSTS.md` section 10.1a).

A single host running the whole compose file (`deploy/docker-compose.yml` as shipped) is right for a demo or a pilot:
it is a single point of failure by design.

---

## 4. Deploying the Kubernetes package

1. **Image**: tag a release (`v*`): CI builds both images, pushes them to the registry and signs them by digest
   (cosign, keyless). Set `images:` in the overlay to that **digest** (the overlays take only a digest), and enforce
   the signature at admission (`deploy/kubernetes/policy/verify-images.yaml`, Kyverno; Azure Policy + Ratify is the
   Azure-native alternative).
2. **Database roles**: the platform runs as a role without schema rights; only the `init-db` init container signs in
   as the schema owner, then grants the runtime role (`SOC_DB_RUNTIME_ROLE`) read / write and an append-only audit
   log. Every connection verifies the server certificate (`sslmode=verify-full`).
3. **Secrets** (never in the manifests or a ConfigMap):
   * Azure: put `soc-database-url` (runtime role, `?sslmode=verify-full&sslrootcert=system`),
     `soc-database-migrator-url` (schema owner), `soc-data-key`, `soc-llm-api-key`, `soc-breakglass-sha256` in Key
     Vault and fill `overlays/azure/keyvault-secrets.yaml` and `serviceaccount.yaml` (vault name, tenant, workload
     identity client id - outputs of `main.bicep`). They are mounted as files and read through `*_FILE` settings;
     nothing is synced into a Kubernetes Secret.
   * On-prem: the operator creates `soc-pg-app` (schema owner) and `soc-pg-ca` (the cluster's CA). Create the rest:
     ```bash
     kubectl -n agentic-soc create secret generic soc-pg-runtime --type=kubernetes.io/basic-auth \
       --from-literal=username=soc_runtime --from-literal=password="$(openssl rand -base64 33)"
     kubectl -n agentic-soc create secret generic soc-platform-secrets \
       --from-literal=SOC_DATA_KEY="$(cat data-key.txt)" --from-literal=SOC_LLM_API_KEY=...
     kubectl -n agentic-soc create secret generic soc-backup-store --from-literal=ACCESS_KEY_ID=... --from-literal=ACCESS_SECRET_KEY=...
     kubectl -n agentic-soc create secret tls soc-tls --cert=soc.crt --key=soc.key
     ```
     Kubernetes Secrets are only base64 in etcd: switch on etcd encryption at rest (`EncryptionConfiguration`, KMS
     provider where available).
   * Connector credentials (the `${VAR}` names in `config/connectors.yaml`) go in the optional Secret
     `soc-connector-secrets` (on Azure: Key Vault objects mounted as files, `<VAR>_FILE` in the settings).
4. **Settings and network**: replace every `CHANGE-ME` in the overlay (`settings.yaml`, `ingress.yaml`, Azure
   `network.yaml` / `database-egress.yaml` subnets). On-prem, label the ingress controller's namespace
   `soc-ingress=true` (the policy admits only the ingress-nginx pods there). Every pod in the namespace starts from
   default-deny: the platform may reach DNS (the cluster resolver), HTTPS, and the database only (Azure: its subnet;
   on-prem: the pooler); the CloudNativePG pods get their own policy (replication, operator, backups) - without it
   default-deny would cut the database off.
5. **Monitoring**: `kubectl apply -k deploy/kubernetes/monitoring` (Prometheus Operator) - ServiceMonitor and alert
   rules (`OPERATIONS.md` - Monitoring).
6. **Check, then apply**:
   ```bash
   kubectl kustomize deploy/kubernetes/overlays/azure | less        # review what will be applied
   kubectl apply -k deploy/kubernetes/overlays/azure
   kubectl -n agentic-soc rollout status deploy/soc-api deploy/soc-scheduler
   kubectl -n agentic-soc exec deploy/soc-api -- python -m soc_platform config check
   ```
7. **Prove it** with the failover drill (section 7) before go-live.

### 4.1 Connection budget

Every process holds up to `SOC_DB_POOL_SIZE + SOC_DB_MAX_OVERFLOW` connections. Keep

`max API replicas x SOC_API_WORKERS x (pool + overflow) + scheduler replicas x (pool + overflow) < max_connections`

With the base values (HPA maximum 4, 1 worker, 10 + 10, 2 schedulers): 4 x 1 x 20 + 2 x 20 = 120, within the
`max_connections` of 300 the on-prem cluster sets. On a managed server, set `max_connections` to match. Raising the
HPA maximum or the workers means raising `max_connections` (or putting PgBouncer in front, as on-prem does).

### 4.2 Sizing

The base requests - 1 vCPU per API pod running one worker process, 250m for the scheduler - fit three 2-vCPU nodes
(one per zone) with room for the cluster's own pods; the sizing basis, the prices and the reason for every
availability choice are in `INFRASTRUCTURE_AND_COSTS.md` section 10. They are starting values: confirm them with a
load test with the organisation's
number of analysts (`scripts/load_test.py`; measured results so far are in `OPERATIONS.md` - Server and database under
load) and from connector volume (`scripts/measure_scale.py`).

---

## 5. Moving stored files from disk into the database

A deployment that started with the file store (the default on a laptop) moves to the database store without loss:

```bash
python -m soc_platform blobs check                  # every reference resolves from this host
python -m soc_platform blobs migrate                # copies each file into `blobs`, repoints its record (idempotent)
# set SOC_BLOB_STORE=database everywhere and restart
python -m soc_platform blobs check                  # now all "database"
python -m soc_platform blobs migrate --delete-files # optional: remove the copied files once committed
```

Reads follow each record's reference, not the setting, so files written before the switch stay readable until they
are migrated. A file that cannot be read is listed, never dropped. The migration is audited (`blobs.migrated`).

---

## 6. Backups and disaster recovery

| What | How | Notes |
|---|---|---|
| Database (all state, including stored files) | Point-in-time recovery: managed backups (cloud: 35 days, geo-redundant in `main.bicep`) or base backups + continuous WAL archiving to a second location, AES-256 encrypted in the bucket (on-prem) | The single thing to back up when `SOC_BLOB_STORE=database` |
| `SOC_DATA_KEY` | **Escrow it in two places** (the production vault and a sealed offline copy or a second vault) | Without it, stored e-mails and reports cannot be decrypted - a lost key is lost data. Rotation keeps old keys for reading (`OPERATIONS.md` - Data protection). |
| Configuration | `config/` in source control; console changes are versioned in the database; `python -m soc_platform config export` | |
| Image | The registry, pinned by digest and signed | |
| Audit chain heads | `audit.anchor` log lines (hourly) in the log platform's write-once retention | After a restore, `python -m soc_platform audit verify --anchor SEQ:HASH` proves the restored history matches what was shipped |

**After any restore**: `GET /api/v1/audit/verify` (the hash chain is intact), `python -m soc_platform blobs check`
(every stored file resolves), `/health` (scheduler running, self-check passing).

**Recovery targets** are the organisation's to set; agree them before go-live. What each layer contributes:

| Layer | Recovery point | Recovery time |
|---|---|---|
| Losing an API / scheduler replica, a node or a zone | Nothing is lost | Requests: the next one goes to another replica. Jobs: within one lease (120 s). |
| Database failover (synchronous standby) | No committed transaction is lost | The service's failover time, plus the readiness period (2 x 5 s) - measure it in the drill |
| Database restore (corruption, deletion) | Back to any point within the backup retention | Restore time of the database size - measure it in the restore drill |
| Losing the region / site | The last geo-replicated backup or WAL segment | Rebuild time of the cluster from the manifests plus the restore - rehearse it |

---

## 7. Failover drill (run before go-live, then twice a year)

| Step | Expected |
|---|---|
| Delete one `soc-api` pod while an analyst works | No error in the console; a replacement pod becomes ready |
| Delete the `soc-scheduler` pod that is running a job (`/health` shows which job) | The other replica runs it within `SOC_JOB_LEASE_SECONDS`; `GET /api/v1/jobs` shows one run, not two |
| Drain a node (`kubectl drain`) | The disruption budgets keep one API and one scheduler serving throughout |
| Fail over the database (portal "forced failover" / `kubectl cnpg promote`) | Requests during the switch get 503 + Retry-After; readiness recovers by itself; no data lost (compare case and audit counts before and after) |
| Restore the database to a point in time in a staging namespace | `audit/verify` ok, `blobs check` clean |
| Engage and release the kill switch | Every replica stops autonomous execution at once (stored in the database) |

---

## 8. Limits to know

* **One primary database.** The platform is active-active on the application tier, not across regions on the
  database: writes go to one primary at a time. Cross-region is disaster recovery (section 6), not active-active.
* **Rate limiting** in the application is per process. With several replicas, the shared limit is the ingress / WAF
  one (both overlays set it).
* **Access-log rows** are queued in memory and written in the background: a process that crashes (not one that
  stops) can lose its last few seconds of access-log rows. Audit events are not affected - they are written in the
  same transaction as the change they record.
* **A scheduler's liveness is local.** The scheduler pods have no HTTP endpoint; their heartbeat thread touches
  `SOC_SCHEDULER_LIVENESS_FILE` every 30 s while the scheduler's threads are alive, and the pod is restarted after
  three minutes without it (a database outage restarts nothing). A job that hangs inside a live scheduler is reported
  on the API's `/health` (`stuck` after `SOC_SCHEDULER_STUCK_SECONDS`, 1800 s) and stops renewing its lease so the
  other replica can retry it - alert on `stuck` (`OPERATIONS.md` - Monitoring).
