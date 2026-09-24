# Azure API Configuration for Email Security System

## Overview
This document clarifies the Azure API integrations and their configuration requirements.

---

## ✅ Azure AI Search (Formerly Azure Cognitive Search)

### What It Is
Azure AI Search is Microsoft's managed search service for semantic search, full-text search, and vector similarity over your threat intelligence database.

### What We Implemented
- ✅ Semantic search over threat indicators (natural language queries)
- ✅ Vector similarity search framework (for finding related IOCs)
- ✅ Faceted search (analyze threat landscape by severity, source, type)
- ✅ Full-text search with advanced filters
- ✅ Automatic index creation and management
- ✅ Graceful degradation if not configured

### Required API Credentials
```env
AZURE_SEARCH_SERVICE=ktaft-search                # Service name (e.g., ktaft-search)
AZURE_SEARCH_API_KEY=your-admin-key-here         # Admin API key
AZURE_SEARCH_ENABLED=true                        # Set to true to enable enrichment
AZURE_SEARCH_INDEX_NAME=threat-indicators        # Default index
```

### How to Get These
1. Go to Azure Portal → Search Services
2. Create or select search service
3. Copy the service name (e.g., "contoso-search" from "contoso-search.search.windows.net")
4. Get admin API key from Settings → Keys → Admin key
5. Add to .env file

### API Usage
- **Endpoint:** `https://{AZURE_SEARCH_SERVICE}.search.windows.net`
- **API Version:** 2023-11-01 (stable)
- **Cost:** Usage-based (queries, indexing, storage)
- **Rate Limits:** Depends on tier (Standard: 3000 req/min, Premium: higher)

### When to Use
- ✅ You want to query threats with natural language ("ransomware payment domains")
- ✅ You need to find similar indicators (vector search)
- ✅ You want threat landscape analysis (faceted by severity/source)
- ✅ You have historical IOC database to index
- ❌ You only need basic lookups (use local IOC cache instead)

---

## ✅ Azure AI Vision (OCR Integration)

### What It Is
High-fidelity cloud-based image analysis for extracting text, barcodes, and hidden URLs from email attachments.

### What We Implemented
- ✅ **Official SDK Migration**: Using `azure-ai-vision-imageanalysis`.
- ✅ **Hybrid Extraction**: Merges local `pyzbar` (fast) with Azure Cloud (high fidelity).
- ✅ **Barcode/QR Support**: Automatic URL extraction from visual codes.
- ✅ **Content Injection**: Extracted text is fed to the Content Agent for phishing analysis.

### Required API Credentials
```env
AZURE_OCR_ENDPOINT=https://kraft-vision.cognitiveservices.azure.com/
AZURE_OCR_KEY=your-ocr-key-here
```

### When to Use
- ✅ You want to extract text from screenshots or posters.
- ✅ You need to detect phishing URLs inside QR codes.
- ✅ You want high-fidelity OCR for non-standard fonts.

---

## ✅ Microsoft Graph API (For Email Remediation)

### What It Is
Microsoft Graph API allows your system to perform real email actions in Exchange/Office 365:
- Quarantine emails
- Insert warning banners
- Add categories/tags
- Move to folders

### What We Implemented
- ✅ App-only authentication (MSAL)
- ✅ Quarantine (move to Junk folder)
- ✅ Warning banner insertion
- ✅ Category/tag addition
- ✅ Simulated mode (safe testing, no real changes)
- ✅ Graceful error handling

### Required API Credentials
```env
GRAPH_TENANT_ID=00000000-0000-0000-0000-000000000000      # Tenant UUID
GRAPH_CLIENT_ID=00000000-0000-0000-0000-000000000000      # App registration UUID
GRAPH_CLIENT_SECRET=your-secret-value-here                # Keep SECURE, rotate regularly
GRAPH_AUTHORITY=https://login.microsoftonline.com         # Default authority URL
GRAPH_SCOPES=https://graph.microsoft.com/.default         # Default scopes
ACTION_SIMULATED_MODE=1                                   # 1=safe, 0=live actions
ACTION_BANNER_ENABLED=0                                   # 1=enable banners
ACTION_QUARANTINE_ENABLED=0                               # 1=enable quarantine
```

### How to Get These
1. Go to Azure AD → App registrations
2. Create new app (or use existing)
3. Copy Application (client) ID
4. Get tenant ID from Azure AD Overview
5. Create client secret (Settings → Certificates & secrets)
6. Grant permissions: Mail.ReadWrite (API Permissions)
7. Add credentials to .env

### API Usage
- **Endpoint:** `https://graph.microsoft.com/v1.0`
- **Auth:** OAuth 2.0 app-only flow (MSAL)
- **Cost:** Included with Microsoft 365 subscription
- **Rate Limits:** 2000 requests/min per app

### When to Use
- ✅ You want automatic email quarantine for high-risk messages
- ✅ You want to insert warning banners
- ✅ You need to categorize/tag suspicious emails
- ✅ You have Exchange/Office 365 tenants
- ❌ You're not using Microsoft email (no Graph support)
- ⚠️ Start in simulated mode (ACTION_SIMULATED_MODE=1) for testing

---

## ✅ Azure OpenAI (Already Configured)

### Status
- ✅ Already has .env entries in template
- ✅ Used for storyline enrichment (optional)
- ✅ Can generate ATT&CK framework mappings

### Configuration
```env
AZURE_OPENAI_ENDPOINT=https://kraft-cyber.cognitiveservices.azure.com/
AZURE_OPENAI_API_KEY=your-api-key-here
AZURE_OPENAI_DEPLOYMENT=gpt-4.1-mini
AZURE_OPENAI_API_VERSION=2024-02-15-preview
STORYLINE_ENABLE_LLM_MITRE_ENRICHMENT=true
```

---

## 📋 Environment File Template Update Needed

Add to `.env.template` (after AZURE_OPENAI section):

```bash
# --- Azure AI Search (for advanced threat intelligence queries) ---
# Optional: Enable for semantic search, vector similarity, and faceted analysis of IOCs
AZURE_SEARCH_SERVICE=
AZURE_SEARCH_API_KEY=
AZURE_SEARCH_ENABLED=false
AZURE_SEARCH_INDEX_NAME=threat-indicators

# --- Microsoft Graph API (for email remediation: quarantine, banner insertion) ---
# Optional: Enable for live email action capability (quarantine, banner, categorization)
GRAPH_TENANT_ID=
GRAPH_CLIENT_ID=
GRAPH_CLIENT_SECRET=
GRAPH_AUTHORITY=https://login.microsoftonline.com
GRAPH_SCOPES=https://graph.microsoft.com/.default
ACTION_SIMULATED_MODE=1
ACTION_BANNER_ENABLED=0
ACTION_QUARANTINE_ENABLED=0
```

---

## 🔐 Security Best Practices

### API Keys in .env
- ✅ Store in .env (git-ignored)
- ✅ Never commit to version control
- ✅ Rotate secrets regularly (especially Graph client secret)
- ✅ Use least-privilege permissions
- ✅ Monitor API usage via Azure Portal
- ❌ Never log API keys
- ❌ Never share credentials

### Testing Safely
1. Start with **simulated mode** enabled (ACTION_SIMULATED_MODE=1)
2. Verify all actions in logs without making real changes
3. Test in **test tenant** before production
4. Gradually enable features:
   - First: Semantic search (read-only)
   - Second: Banners (low risk)
   - Third: Quarantine (production only)

---

## 🚀 Recommended Setup Order

### Phase 1: Start (No Azure APIs needed)
- Local IOC cache (already implemented)
- Request deduplication (already implemented)
- Simulated action mode (default)

### Phase 2: Optional Enhancements (Add as needed)
1. **Azure AI Search** (if you want semantic threat queries)
   - Get service name and admin key
   - Set AZURE_SEARCH_ENABLED=true
   - Test semantic queries on IOC dataset

2. **Microsoft Graph** (if you want live email actions)
   - Create app registration in Azure AD
   - Get credentials
   - Keep ACTION_SIMULATED_MODE=1 initially
   - Test with simulation first
   - Enable ACTION_BANNER_ENABLED=true for low-risk actions
   - Only enable ACTION_QUARANTINE_ENABLED=true in production

### Phase 3: Advanced (After validation)
- Vector search (requires embedding model)
- Campaign clustering with Azure Search
- Advanced remediation policies

---

## 📞 Support & Troubleshooting

### Azure AI Search Not Working?
- Verify service name (just name, not full URL)
- Check API key is admin key (not query key)
- Ensure index name is correct
- Check Azure portal for service status
- Verify network/firewall doesn't block access

### Graph API Returning 403?
- Verify app has Mail.ReadWrite permission
- Check admin has granted tenant consent
- Verify client secret hasn't expired
- Ensure tenant ID matches where app is registered
- Check if mailbox exists and user has access

### Want to Enable Later?
- All APIs are **optional** and gracefully degrade
- System works fine without them
- Add credentials to .env when ready
- Set feature flags to enable
- No code changes needed

---

## API Pricing (Rough Estimates)

| Service | Pricing | When to Enable |
|---------|---------|---|
| Azure AI Search | $0.25/hour (Standard) | When you have 1000+ IOCs to search |
| Microsoft Graph | Free (with M365) | When you need email remediation |
| Azure OpenAI | ~$0.005/1K tokens | Optional storyline enrichment |

---

## Minimal vs Full Setup

### Minimal Setup (Local only)
```env
# Only requires local resources
REDIS_URL=redis://redis:6379/0
DATABASE_URL=postgresql://postgres:postgres@database:5432/email_security
REQUEST_DEDUPLICATION_ENABLED=true
```
**Result:** Works fully, but no external API calls

### Full Setup (All Azure services)
```env
# Add all three Azure APIs
AZURE_SEARCH_ENABLED=true
GRAPH_TENANT_ID=your-tenant
AZURE_OPENAI_ENDPOINT=your-endpoint
```
**Result:** Maximum capabilities - semantic search, email actions, LLM enrichment
