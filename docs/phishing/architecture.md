# Detailed Agentic System Architecture

This document maps the full end-to-end architecture and provides deep internal flow diagrams for every analytical agent and the LangGraph decision layer.

---

## 0. Overall System Architecture

This graph shows the complete data plane and control plane from API ingress to final action dispatch.

```mermaid
graph TD
    classDef ext fill:#1f2937,stroke:#9ca3af,color:#fff
    classDef core fill:#1e3a8a,stroke:#60a5fa,color:#fff
    classDef bus fill:#0f766e,stroke:#2dd4bf,color:#fff
    classDef agent fill:#111827,stroke:#3b82f6,color:#fff
    classDef orch fill:#7c2d12,stroke:#fb923c,color:#fff
    classDef data fill:#14532d,stroke:#34d399,color:#fff
    classDef action fill:#4c1d95,stroke:#c084fc,color:#fff

    subgraph Ingress[Ingress API and Parsing]
        API[FastAPI /analyze-email]:::core --> Auth[JWT or API Key Validation]:::core
        Auth --> Rate[Rate Limit and Tenant Quota]:::core
        Rate --> Parse[Email Parser MIME plus Header plus Body]:::core
        Parse --> Norm[Canonical Event Builder with Correlation ID]:::core
        Norm --> OCR[Azure AI Vision OCR for image/PDF analysis]:::core
        OCR --> IOC[IOC Extraction URLs IPs Domains Hashes]:::core
        IOC --> Envelope[Envelope Serializer JSON schema validated]:::core
    end

    subgraph Messaging[Asynchronous Messaging Fabric]
        Envelope --> EX[RabbitMQ Exchange email.analysis.v1]:::bus
        EX --> QH[Queue header.agent]:::bus
        EX --> QC[Queue content.agent]:::bus
        EX --> QU[Queue url.agent]:::bus
        EX --> QA[Queue attachment.agent]:::bus
        EX --> QS[Queue sandbox.agent]:::bus
        EX --> QT[Queue threatintel.agent]:::bus
        EX --> QB[Queue userbehavior.agent]:::bus
    end

    subgraph Agents[Parallel Agent Execution]
        QH --> HA[Header Agent Worker]:::agent
        QC --> CA[Content Agent Worker]:::agent
        QU --> UA[URL Agent Worker]:::agent
        QA --> AA[Attachment Agent Worker]:::agent
        QS --> SA[Sandbox Agent Worker]:::agent
        QT --> TA[Threat Intel Agent Worker]:::agent
        QB --> BA[User Behavior Agent Worker]:::agent

        HA --> AR[Agent Result Topic]:::bus
        CA --> AR
        UA --> AR
        AA --> AR
        SA --> AR
        TA --> AR
        BA --> AR
    end

    subgraph Orchestration[LangGraph Decision and Explainability]
        AR --> Intake[State Collector with timeout policy]:::orch
        Intake --> Score[Weighted Scoring Engine]:::orch
        Score --> Cor[Cross-Agent Correlation Matrix]:::orch
        Cor --> Gate{Risk Threshold Gate}:::orch
        Gate --> CF[Counterfactual Analyzer]:::orch
        CF --> Reason[LLM Security Reasoner]:::orch
        Reason --> Story[Threat Storyline Generator]:::orch
    end

    subgraph StorageAndAction[Persistence and Response]
        Story --> Persist[Persist Analysis Record]:::data
        Persist --> PG[(PostgreSQL)]:::data
        Persist --> Hist[(Feature and Decision History)]:::data

        Persist --> Policy[Response Policy Evaluator]:::action
        Policy --> Garuda{Trigger Garuda Hunt}:::action
        Garuda -->|yes| Hunt[Garuda Endpoint Hunt API]:::action
        Garuda -->|no| Dispatch[Action Dispatcher]:::action
        Hunt --> Dispatch
        Dispatch --> Quarantine[Mailbox Quarantine]:::action
        Dispatch --> Ticket[SOC Ticket and Alert Routing]:::action
        Dispatch --> Notify[Analyst Notification Webhook]:::action
    end

    subgraph Realtime[Realtime Analyst Experience]
        HA -. metrics and interim risk .-> Stream[Redis PubSub Stream]:::ext
        CA -. metrics and interim risk .-> Stream
        UA -. metrics and interim risk .-> Stream
        AA -. metrics and interim risk .-> Stream
        SA -. metrics and interim risk .-> Stream
        TA -. metrics and interim risk .-> Stream
        BA -. metrics and interim risk .-> Stream
        Persist -. final verdict .-> Stream
        Stream --> UI[SOC Dashboard WebSocket Client]:::ext
    end
```

---

## 1. Decision Layer (LangGraph Orchestrator)

The orchestrator is modeled as a state graph with strict transitions, timeout handling, and explainability stages.

```mermaid
graph TD
    classDef io fill:#0f172a,stroke:#3b82f6,color:#fff
    classDef logic fill:#312e81,stroke:#a78bfa,color:#fff
    classDef llm fill:#7c2d12,stroke:#fdba74,color:#fff
    classDef data fill:#14532d,stroke:#34d399,color:#fff
    classDef risk fill:#7f1d1d,stroke:#fca5a5,color:#fff

    Start([Result Event Bundle]):::io --> Schema[Validate against result schema]:::logic
    Schema --> Merge[Merge into correlation scoped state object]:::logic
    Merge --> Check{All required agents present}:::logic

    Check -->|no| Cache[Store partial state in Redis hash]:::data
    Cache --> Timer{Timeout reached}:::logic
    Timer -->|no| Wait[Wait for remaining agents]:::io
    Wait --> Merge
    Timer -->|yes| Degrade[Mark missing agents and apply fallback priors]:::logic

    Check -->|yes| Normalize[Normalize each agent score and confidence]:::logic
    Degrade --> Normalize

    subgraph Scoring[Scoring and Correlation]
        Normalize --> W1[Apply per-agent base weights]:::logic
        W1 --> W2[Adjust by confidence calibration curves]:::logic
        W2 --> Corr1[Run cross-agent correlation rules]:::logic
        Corr1 --> Corr2[Run learned interaction matrix boost penalty]:::logic
        Corr2 --> Contr[Compute contradiction penalty]:::logic
        Contr --> FinalRisk[Compute final composite risk score]:::risk
    end

    FinalRisk --> Verdict{Map score to verdict band}:::logic
    Verdict -->|>=0.85| V1[Malicious]:::risk
    Verdict -->|0.65-0.84| V2[High Risk]:::risk
    Verdict -->|0.40-0.64| V3[Suspicious]:::risk
    Verdict -->|<0.40| V4[Safe]:::risk

    V1 --> ExplainSeed[Build explainability feature bundle]:::llm
    V2 --> ExplainSeed
    V3 --> ExplainSeed
    V4 --> ExplainSeed

    subgraph Explainability[Counterfactual and Narrative]
        ExplainSeed --> CF[Counterfactual engine minimal changes to flip class]:::llm
        CF --> Why[Reason extraction top positive and negative contributors]:::llm
        Why --> LLM[Azure OpenAI Reasoning and Attack Synthesis]:::llm
        LLM --> Story[Chronological attack storyline synthesis]:::llm
        Story --> Rec[Action recommendation generation]:::llm
    end

    Rec --> Persist[Persist orchestrator output plus trace]:::data
    Persist --> Out([Final Analysis Payload]):::io
```

---

## 2. Header Agent Architecture

Detects identity spoofing and transport anomalies from the full transit path.

```mermaid
graph TD
    classDef in fill:#334155,stroke:#94a3b8,color:#fff
    classDef proc fill:#1e3a8a,stroke:#60a5fa,color:#fff
    classDef check fill:#0f766e,stroke:#2dd4bf,color:#fff
    classDef out fill:#14532d,stroke:#34d399,color:#fff

    In([Raw RFC822 Headers]):::in --> Parse[Structured header parser]:::proc
    Parse --> Canon[Canonicalize header keys and multiline fields]:::proc
    Canon --> Extract[Extract from reply-to return-path sender-id message-id]:::proc
    Canon --> Recv[Extract ordered Received chain]:::proc
    Canon --> Auth[Extract SPF DKIM DMARC ARC auth-results]:::proc

    subgraph AuthChecks[Authentication Validation]
        Auth --> SPFCheck[SPF alignment and include chain inspection]:::check
        Auth --> DKIMCheck[DKIM selector and domain alignment check]:::check
        Auth --> DMARCCheck[DMARC policy and alignment evaluation]:::check
        Auth --> ARCCheck[ARC seal chain integrity]:::check
        SPFCheck --> AuthScore[Auth trust subscore]:::proc
        DKIMCheck --> AuthScore
        DMARCCheck --> AuthScore
        ARCCheck --> AuthScore
    end

    subgraph RouteChecks[Transport Path Analysis]
        Recv --> HopNorm[Normalize hop IP host timestamp]:::check
        HopNorm --> Geo[GeoIP and ASN lookup per hop]:::check
        Geo --> RBL[Realtime blocklist checks for source hops]:::check
        RBL --> Drift[Detect impossible geo time travel and ASN drift]:::check
        Drift --> Relay[Open relay or suspicious relay fingerprint]:::check
        Relay --> RouteScore[Route anomaly subscore]:::proc
    end

    subgraph IdentityChecks[Identity Consistency]
        Extract --> DomGraph[Build sender identity graph]:::check
        DomGraph --> Misalign[From versus Reply-To versus Return-Path mismatch]:::check
        Misalign --> Lookalike[Lookalike domain and homoglyph test]:::check
        Lookalike --> MID[Message-ID domain consistency check]:::check
        MID --> IdentityScore[Identity mismatch subscore]:::proc
    end

    AuthScore --> Fuse[Weighted fusion with confidence]:::proc
    RouteScore --> Fuse
    IdentityScore --> Fuse
    Fuse --> Reason[Generate machine-readable reasons list]:::out
    Reason --> Out([Header Agent Score plus Confidence plus Evidence]):::out
```

---

## 3. Content Agent Architecture

Runs privacy-safe semantic phishing detection over cleaned body text and structural cues.

```mermaid
graph TD
    classDef ingest fill:#1f2937,stroke:#9ca3af,color:#fff
    classDef prep fill:#1e3a8a,stroke:#60a5fa,color:#fff
    classDef ml fill:#7c2d12,stroke:#fb923c,color:#fff
    classDef rule fill:#0f766e,stroke:#2dd4bf,color:#fff
    classDef out fill:#14532d,stroke:#34d399,color:#fff

    In([Plaintext HTML and OCR text]):::ingest --> Decode[Charset decode and control char cleanup]:::prep
    Decode --> Strip[HTML to text with DOM section retention]:::prep
    Strip --> Segment[Segment subject greeting body footer CTA blocks]:::prep
    Segment --> PII[PII and secret masking pass]:::prep
    PII --> Norm[Normalize unicode whitespace and punctuation]:::prep

    subgraph EmbeddingAndInference[SLM Inference Path]
        Norm --> Tok[Tokenizer with max length and truncation policy]:::ml
        Tok --> Model[TinyBERT phishing classifier]:::ml
        Model --> Logits[Raw logits]:::ml
        Logits --> Calib[Temperature calibration and probability smoothing]:::ml
        Calib --> MLScore[Semantic phishing probability]:::ml
    end

    subgraph LinguisticHeuristics[Deterministic Cue Extractors]
        Norm --> Intent[Urgency coercion and fear language detector]:::rule
        Norm --> Brand[Brand impersonation and credential request detector]:::rule
        Norm --> CTA[Call to action plus payment reset patterns]:::rule
        Norm --> Obfus[Obfuscation and unicode trick detector]:::rule
        Intent --> RuleScore[Heuristic score]:::rule
        Brand --> RuleScore
        CTA --> RuleScore
        Obfus --> RuleScore
    end

    subgraph ContextSignals[Contextual Adjustments]
        Segment --> Tone[Conversation continuity and thread break check]:::rule
        Segment --> Lang[Language mismatch to tenant profile]:::rule
        Tone --> CtxScore[Context anomaly score]:::rule
        Lang --> CtxScore
    end

    MLScore --> Fuse[Blend semantic heuristic and context scores]:::prep
    RuleScore --> Fuse
    CtxScore --> Fuse
    Fuse --> Explain[Top contributing spans and rationales]:::out
    Explain --> Out([Content Agent Score plus Confidence plus Evidence]):::out
```

---

## 4. URL Agent Architecture

Performs canonicalization, lexical feature engineering, model ensemble scoring, and campaign-level aggregation.

```mermaid
graph TD
    classDef io fill:#334155,stroke:#94a3b8,color:#fff
    classDef feat fill:#1e3a8a,stroke:#60a5fa,color:#fff
    classDef ml fill:#312e81,stroke:#a78bfa,color:#fff
    classDef out fill:#14532d,stroke:#34d399,color:#fff

    In([Extracted URL Set]):::io --> Dedup[Normalize and de-duplicate URLs]:::feat
    Dedup --> Resolve[Resolve redirects shorteners and punycode]:::feat
    Resolve --> Loop[Iterate URL candidates]:::feat

    subgraph FeaturePipeline[Per URL Feature Engineering]
        Loop --> Lex[Lexical features length depth tokens separators]:::feat
        Loop --> Host[Hostname features TLD age ASN entropy]:::feat
        Loop --> Path[Path query fragment suspicious token metrics]:::feat
        Loop --> Brand[Brand similarity and typo distance features]:::feat
        Loop --> Cred[Credential bait phrase and form endpoint cues]:::feat
        Lex --> Vec[Feature vector assembler]:::feat
        Host --> Vec
        Path --> Vec
        Brand --> Vec
        Cred --> Vec
    end

    subgraph ModelEnsemble[Model Inference]
        Vec --> XGB[XGBoost probability]:::ml
        Vec --> RF[Random Forest probability]:::ml
        Vec --> LR[Logistic calibration model]:::ml
        XGB --> Stack[Stacking combiner]:::ml
        RF --> Stack
        LR --> Stack
        Stack --> URLRisk[Per URL risk and confidence]:::ml
    end

    URLRisk --> Rank[Rank URLs by risk and exploitability]:::feat
    Rank --> Agg[Aggregate email-level URL risk max plus mean plus dispersion]:::feat
    Agg --> Reasons[Attach per URL evidence snippets]:::out
    Reasons --> Out([URL Agent Score plus Confidence plus Evidence]):::out
```

---

## 5. Attachment and OCR Agent Architecture

Combines static file triage, safe extraction, OCR analysis, and URL re-injection for hidden-link detection.

```mermaid
graph TD
    classDef io fill:#14532d,stroke:#34d399,color:#fff
    classDef proc fill:#1e3a8a,stroke:#60a5fa,color:#fff
    classDef det fill:#7c2d12,stroke:#fb923c,color:#fff
    classDef out fill:#312e81,stroke:#a78bfa,color:#fff

    In([Attachment Bundle]):::io --> Manifest[Build attachment manifest name size mime hash]:::proc
    Manifest --> Type{File class}:::proc

    subgraph ExecutablePath[Executable Script Archive Path]
        Type -->|exe script archive| Static[Static parser and unpacker]:::det
        Static --> Magic[Magic-byte versus extension mismatch check]:::det
        Static --> Macro[Macro or script capability detector]:::det
        Static --> Entropy[Packed or obfuscated section detector]:::det
        Static --> Yara[YARA ruleset scan]:::det
        Magic --> SScore[Static threat subscore]:::proc
        Macro --> SScore
        Entropy --> SScore
        Yara --> SScore
    end

    subgraph DocumentImagePath[Document and Image Path]
        Type -->|pdf doc image| SafeRender[Safe rasterization in isolated worker]:::det
        SafeRender --> OCR[Azure AI Vision Cloud Analysis]:::det
        OCR --> Hidden[Hidden text layer and tiny font detector]:::det
        Hidden --> URLExtract[Extract embedded and visual URLs]:::det
        URLExtract --> Reinjection[Send discovered URLs to URL analysis queue]:::proc
        OCR --> DScore[Document deception subscore]:::proc
        Hidden --> DScore
    end

    subgraph HashIntel[Hash Reputation]
        Manifest --> HashRep[Hash cache and TI reputation check]:::det
        HashRep --> HScore[Hash intelligence subscore]:::proc
    end

    SScore --> Fuse[Risk fusion with confidence weighting]:::proc
    DScore --> Fuse
    HScore --> Fuse
    Reinjection --> Fuse
    Fuse --> Evidence[Evidence bundle indicators matched rules discovered URLs]:::out
    Evidence --> Out([Attachment Agent Score plus Confidence plus Evidence]):::out
```

---

## 6. Sandbox Agent Architecture

Detonates suspicious artifacts in isolated runtime with behavioral telemetry and kill-chain mapping.

```mermaid
graph TD
    classDef infra fill:#1f2937,stroke:#9ca3af,color:#fff
    classDef exec fill:#7c2d12,stroke:#fb923c,color:#fff
    classDef detect fill:#0f766e,stroke:#2dd4bf,color:#fff
    classDef out fill:#14532d,stroke:#34d399,color:#fff

    In([Payload Candidate]):::infra --> Prep[Pre-execution safety checks and policy gate]:::infra
    Prep --> Stage[Stage payload into ephemeral tmpfs workspace]:::infra
    Stage --> Build[Create isolated container or microVM profile]:::infra

    subgraph Runtime[Detonation Runtime]
        Build --> Net[Apply egress control policy full deny or sinkhole]:::exec
        Net --> Exec[Controlled execution wrapper timeout and args policy]:::exec
        Exec --> Sys[Collect syscall and process tree telemetry]:::detect
        Exec --> FS[Collect file write rename and dropper telemetry]:::detect
        Exec --> Reg[Collect registry and autorun persistence telemetry]:::detect
        Exec --> Mem[Collect memory injection and hollowing telemetry]:::detect
        Exec --> DNS[Collect DNS and network callback telemetry]:::detect
    end

    Sys --> Behave[Behavioral rule engine mapped to MITRE ATTACK tactics]:::detect
    FS --> Behave
    Reg --> Behave
    Mem --> Behave
    DNS --> Behave

    Behave --> Family[Malware family fingerprint matcher]:::detect
    Family --> Risk[Behavioral risk scorer severity and confidence]:::out
    Risk --> Cleanup[Destroy runtime wipe tmpfs and revoke artifacts]:::infra
    Cleanup --> Out([Sandbox Agent Score plus Confidence plus Timeline]):::out
```

---

## 7. Threat Intel Agent Architecture

Performs cache-first IOC enrichment with provider fan-out, normalization, reliability weighting, and verdict synthesis.

```mermaid
graph TD
    classDef in fill:#14532d,stroke:#34d399,color:#fff
    classDef proc fill:#1e3a8a,stroke:#60a5fa,color:#fff
    classDef api fill:#7c2d12,stroke:#fb923c,color:#fff
    classDef out fill:#312e81,stroke:#a78bfa,color:#fff

    In([IOCs domains IPs URLs hashes]):::in --> Norm[Normalize and type classify IOC set]:::proc
    Norm --> Cache[Lookup local SQLite cache with staleness policy]:::proc
    Cache --> Hit{Fresh cache entries}:::proc

    Hit -->|yes| CachedScore[Use cached verdict confidence and source set]:::proc
    Hit -->|partial or no| Queue[Prepare unresolved IOC query batch]:::proc

    subgraph ProviderFanout[External Intelligence Providers]
        Queue --> AZS[Azure AI Search Semantic Search]:::api
        Queue --> VT[VirusTotal adapter]:::api
        Queue --> OTX[AlienVault OTX adapter]:::api
        Queue --> Abuse[AbuseIPDB adapter]:::api
        Queue --> Phish[OpenPhish feed adapter]:::api
        Queue --> MZ[MalwareBazaar adapter]:::api
        Queue --> URLH[URLHaus adapter]:::api
    end

    VT --> Parse[Normalize provider responses into common schema]:::proc
    OTX --> Parse
    Abuse --> Parse
    Phish --> Parse
    MZ --> Parse
    URLH --> Parse

    Parse --> Reliability[Apply source reliability and recency weights]:::proc
    Reliability --> Consensus[Per IOC maliciousness consensus score]:::proc
    Consensus --> CacheWrite[Write back cache with TTL and provenance]:::proc
    CacheWrite --> Merge[Merge cached and fresh IOC results]:::proc
    CachedScore --> Merge

    Merge --> Rollup[Email-level TI rollup malicious ratio severity boost]:::out
    Rollup --> Evidence[Attach IOC level evidence and provider hits]:::out
    Evidence --> Out([Threat Intel Score plus Confidence plus Evidence]):::out
```

---

## 8. User Behavior Agent Architecture

Builds recipient and sender interaction baselines, detects anomalies, and computes contextual risk uplift.

```mermaid
graph TD
    classDef in fill:#312e81,stroke:#a78bfa,color:#fff
    classDef feat fill:#1e3a8a,stroke:#60a5fa,color:#fff
    classDef ml fill:#0f766e,stroke:#2dd4bf,color:#fff
    classDef out fill:#14532d,stroke:#34d399,color:#fff

    In([Context from to cc timestamp domain role]):::in --> Hist[Fetch communication history from Postgres]:::feat
    Hist --> Clean[Filter by retention policy and tenant scope]:::feat

    subgraph BaselineModel[Behavior Baseline Construction]
        Clean --> Contact[Contact graph first seen and frequency features]:::feat
        Clean --> Time[Time-of-day and weekday behavior profile]:::feat
        Clean --> Thread[Thread continuity and reply chain consistency]:::feat
        Clean --> Role[Role sensitivity VIP finance admin multiplier]:::feat
        Clean --> Geo[Sender geo and ASN familiarity profile]:::feat
        Contact --> FVec[Feature vector builder]:::feat
        Time --> FVec
        Thread --> FVec
        Role --> FVec
        Geo --> FVec
    end

    subgraph AnomalyScoring[Anomaly and Risk Estimation]
        FVec --> Iso[Isolation Forest anomaly score]:::ml
        FVec --> XGB[XGBoost contextual risk score]:::ml
        FVec --> Rules[Deterministic penalties first contact odd hour VIP target]:::ml
        Iso --> Blend[Blend model and rule outputs with confidence]:::ml
        XGB --> Blend
        Rules --> Blend
    end

    Blend --> Explain[Generate anomaly reasons and baseline deltas]:::out
    Explain --> Out([User Behavior Score plus Confidence plus Evidence]):::out
```
