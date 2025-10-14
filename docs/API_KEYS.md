# API Key Configuration Guide

This guide explains how to obtain, configure, and manage API keys for enhanced reconnaissance features.

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Supported Services](#supported-services)
4. [Configuration Methods](#configuration-methods)
5. [Security Best Practices](#security-best-practices)
6. [Free Alternatives](#free-alternatives)

---

## Overview

The Security Reconnaissance Platform can leverage various third-party APIs to enhance subdomain discovery and intelligence gathering. **API keys are entirely optional** - the platform works without them, but certain features provide enhanced results when configured.

### Do I Need API Keys?

**No!** The platform is fully functional without any API keys. Most tools work without external APIs:

- ✅ Certificate Transparency (crt.sh) - **Free, no key required**
- ✅ DNS brute-forcing - **Local**
- ✅ HTTP probing - **Local**
- ✅ Port scanning - **Local**
- ✅ Passive subdomain enumeration - **Free tools**

### What Do API Keys Enable?

API keys provide:

- 📈 **Higher rate limits** - Faster scanning
- 🔍 **Additional data sources** - More comprehensive results
- 🏢 **Company acquisition data** - Corporate structure mapping
- 📊 **Historical DNS data** - Subdomain history
- 🌐 **Internet-wide scanning** - Shodan/Censys data

---

## Quick Start

### Check Current Configuration

```bash
# List configured API keys (doesn't show actual keys)
python main.py --list-api-keys

# Or via API
curl http://localhost:8000/api/config/api-keys
```

### Set an API Key

```bash
# Command line (interactive, hidden input)
python main.py --set-api-key whoisxml <YOUR_KEY>

# Or via API
curl -X POST http://localhost:8000/api/config/api-keys/whoisxml \
  -H "Content-Type: application/json" \
  -d '{"api_key": "YOUR_KEY_HERE"}'
```

### Test API Key

```bash
# Test if key works
python main.py --test-api-key whoisxml
```

### Remove API Key

```bash
python main.py --remove-api-key whoisxml
```

---

## Supported Services

### 1. WhoIsXMLAPI

**Purpose:** Company acquisition discovery (horizontal enumeration)

**Features:**
- Discover parent/subsidiary companies
- Find related domains
- Corporate structure mapping

**Free Tier:** 500 requests/month  
**Paid Plans:** Starting at $20/month

**How to Obtain:**
1. Go to [WhoisXMLAPI.com](https://whoisxmlapi.com/)
2. Sign up for free account
3. Navigate to "My Products" → "Account"
4. Copy your API key
5. Add to platform: `python main.py --set-api-key whoisxml YOUR_KEY`

**Configuration:**
```bash
export WHOISXML_API_KEY="your_key_here"
# Or
python main.py --set-api-key whoisxml your_key_here
```

**Used By:**
- Horizontal Enumeration → Acquisition Discovery
- Company relationship mapping

---

### 2. Censys

**Purpose:** Certificate Transparency logs, internet-wide scanning

**Features:**
- Historical certificate data
- IPv4 host discovery
- Service fingerprinting
- SSL/TLS analysis

**Free Tier:** 250 queries/month  
**Paid Plans:** Starting at $99/month (Enterprise)

**How to Obtain:**
1. Go to [Censys.io](https://censys.io/)
2. Create free account
3. Navigate to "Account" → "API"
4. Copy API ID and Secret
5. Add to platform: `python main.py --set-api-key censys "API_ID:SECRET"`

**Configuration:**
```bash
export CENSYS_API_KEY="api_id:secret"
# Or
python main.py --set-api-key censys "api_id:secret"
```

**Used By:**
- Passive Enumeration → Certificate Transparency Scanner
- SSL/TLS certificate discovery

**Note:** Censys API v2 is used. Format: `API_ID:API_SECRET`

---

### 3. Shodan

**Purpose:** Internet-wide device and service discovery

**Features:**
- IoT device discovery
- Service banner grabbing
- Historical port scan data
- Vulnerability detection

**Free Tier:** 100 results/month  
**Paid Plans:** 
- Membership: $59 (one-time, lifetime)
- Enterprise: Custom pricing

**How to Obtain:**
1. Go to [Shodan.io](https://www.shodan.io/)
2. Create free account
3. Navigate to "Account"
4. Copy API Key
5. Add to platform: `python main.py --set-api-key shodan YOUR_KEY`

**Configuration:**
```bash
export SHODAN_API_KEY="your_key_here"
# Or
python main.py --set-api-key shodan your_key_here
```

**Used By:**
- ASN lookup and IP range discovery
- Port and service enumeration

---

### 4. SecurityTrails

**Purpose:** Historical DNS data, subdomain discovery

**Features:**
- Historical DNS records
- Subdomain enumeration
- WHOIS data
- DNS analytics

**Free Tier:** 50 queries/month  
**Paid Plans:** Starting at $99/month

**How to Obtain:**
1. Go to [SecurityTrails.com](https://securitytrails.com/)
2. Sign up for free account
3. Navigate to "API"
4. Generate API key
5. Add to platform: `python main.py --set-api-key securitytrails YOUR_KEY`

**Configuration:**
```bash
export SECURITYTRAILS_API_KEY="your_key_here"
# Or
python main.py --set-api-key securitytrails your_key_here
```

**Used By:**
- Passive subdomain enumeration
- Historical DNS analysis

---

### 5. VirusTotal

**Purpose:** Subdomain discovery, malware analysis integration

**Features:**
- Subdomain discovery via passive DNS
- Domain reputation
- File/URL scanning
- Threat intelligence

**Free Tier:** 500 requests/day  
**Paid Plans:** Custom pricing

**How to Obtain:**
1. Go to [VirusTotal.com](https://www.virustotal.com/)
2. Create free account
3. Navigate to user menu → "API Key"
4. Copy API key
5. Add to platform: `python main.py --set-api-key virustotal YOUR_KEY`

**Configuration:**
```bash
export VIRUSTOTAL_API_KEY="your_key_here"
# Or
python main.py --set-api-key virustotal your_key_here
```

**Used By:**
- Passive subdomain enumeration
- Domain reputation checks

---

### 6. GitHub Personal Access Token

**Purpose:** Discovering subdomains from GitHub code/issues/commits

**Features:**
- Search code repositories
- Higher API rate limits (5000 req/hour vs 60)
- Access to private repositories (if token has access)

**Free Tier:** Unlimited (with rate limits)  
**Cost:** Free

**How to Obtain:**
1. Go to [GitHub Settings](https://github.com/settings/tokens)
2. Click "Generate new token (classic)"
3. Give it a name (e.g., "Recon Platform")
4. Select scopes: `public_repo` or `repo` (if you need private repos)
5. Generate token and copy immediately (shown only once!)
6. Add to platform: `python main.py --set-api-key github YOUR_TOKEN`

**Configuration:**
```bash
export GITHUB_TOKEN="ghp_xxxxxxxxxxxx"
# Or
python main.py --set-api-key github ghp_xxxxxxxxxxxx
```

**Used By:**
- Active Enumeration → GitHub Subdomains tool
- Source code scanning for domains

---

### 7. GitLab Personal Access Token

**Purpose:** Discovering subdomains from GitLab repositories

**Features:**
- Search GitLab repositories
- Higher rate limits
- Access to group projects

**Free Tier:** Unlimited  
**Cost:** Free

**How to Obtain:**
1. Go to [GitLab User Settings](https://gitlab.com/-/profile/personal_access_tokens)
2. Add new token
3. Name: "Recon Platform"
4. Scopes: `read_api`, `read_repository`
5. Create token
6. Add to platform: `python main.py --set-api-key gitlab YOUR_TOKEN`

**Configuration:**
```bash
export GITLAB_TOKEN="glpat-xxxxxxxxxxxx"
# Or
python main.py --set-api-key gitlab glpat-xxxxxxxxxxxx
```

**Used By:**
- Active Enumeration → GitLab Subdomains tool

---

## Configuration Methods

### Method 1: Command Line (Recommended)

```bash
# Interactive (hides input)
python main.py --set-api-key <service> <key>

# View configured services
python main.py --list-api-keys

# Test key
python main.py --test-api-key <service>

# Remove key
python main.py --remove-api-key <service>
```

### Method 2: Environment Variables

Add to your `.env` file or shell profile:

```bash
# .env file
WHOISXML_API_KEY=your_key_here
CENSYS_API_KEY=api_id:secret
SHODAN_API_KEY=your_key_here
SECURITYTRAILS_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
GITHUB_TOKEN=ghp_your_token_here
GITLAB_TOKEN=glpat_your_token_here
```

### Method 3: Configuration File

Edit `config/api_keys.enc` (encrypted storage):

```bash
# The platform automatically encrypts keys
# Use CLI commands for safest management
python main.py --set-api-key <service> <key>
```

### Method 4: REST API

```bash
# Set key
curl -X POST http://localhost:8000/api/config/api-keys/whoisxml \
  -H "Content-Type: application/json" \
  -d '{"api_key": "YOUR_KEY"}'

# List services
curl http://localhost:8000/api/config/api-keys

# Response: {"services": ["whoisxml", "censys"]}
```

---

## Security Best Practices

### 🔒 Storage Security

- ✅ API keys are encrypted at rest using Fernet (symmetric encryption)
- ✅ Master key stored with 0600 permissions (owner-only access)
- ✅ Keys never logged or displayed in output
- ✅ Environment variables cleared after loading

### 🔑 Key Management

1. **Use Separate Keys for Different Environments**
   - Development: Limited key
   - Production: Full-access key

2. **Rotate Keys Regularly**
   ```bash
   python main.py --remove-api-key <service>
   python main.py --set-api-key <service> <new_key>
   ```

3. **Limit Key Permissions**
   - Only grant necessary scopes
   - GitHub: `public_repo` instead of `repo` if possible
   - Use read-only keys when available

4. **Monitor Key Usage**
   - Check API provider dashboards for unusual activity
   - Set up usage alerts
   - Review logs regularly

### 🚨 What NOT to Do

- ❌ Don't commit API keys to version control
- ❌ Don't share keys between users
- ❌ Don't use production keys for testing
- ❌ Don't store keys in plain text files
- ❌ Don't expose keys in logs or error messages

### 🔐 Protecting Keys

Add to `.gitignore`:
```
# API Keys and Secrets
.env
config/api_keys.enc
config/.master_key
*.key
*.secret
```

---

## Free Alternatives

You can achieve excellent results without any paid API keys:

### Subdomain Discovery

| Feature | Free Alternative |
|---------|------------------|
| Certificate Transparency | ✅ crt.sh (no key required) |
| Subdomain brute-forcing | ✅ PureDNS with wordlists |
| Passive enumeration | ✅ subfinder, assetfinder (built-in) |
| Historical data | ✅ Wayback Machine via gau/waybackurls |

### Intelligence Gathering

| Feature | Free Alternative |
|---------|------------------|
| Port scanning | ✅ naabu (local) |
| HTTP probing | ✅ httpx (local) |
| Technology detection | ✅ Wappalyzer/httpx built-in |
| DNS enumeration | ✅ dnsx (local) |

### When to Consider Paid APIs

Consider paid APIs if you:
- Need **historical DNS data** (SecurityTrails)
- Want **internet-wide scanning** (Shodan/Censys)
- Require **corporate intelligence** (WhoisXML)
- Need **higher rate limits** (VirusTotal premium)
- Want **comprehensive threat data** (paid threat feeds)

---

## Feature Comparison Matrix

| Feature | Free Tools | WhoIsXML | Censys | Shodan | SecurityTrails | VirusTotal |
|---------|-----------|----------|---------|---------|----------------|------------|
| **Subdomain Discovery** | ✅ Good | ⭐ Excellent | ⭐ Excellent | ✅ Good | ⭐ Excellent | ✅ Good |
| **Certificate Data** | ✅ Good | ❌ | ⭐ Excellent | ❌ | ✅ Good | ✅ Good |
| **Historical DNS** | ❌ | ❌ | ✅ Limited | ❌ | ⭐ Excellent | ✅ Limited |
| **Port Scanning** | ⭐ Excellent (local) | ❌ | ⭐ Excellent | ⭐ Excellent | ❌ | ❌ |
| **Company Data** | ❌ | ⭐ Excellent | ❌ | ❌ | ❌ | ❌ |
| **Rate Limits** | Varies | 500/mo | 250/mo | 100/mo | 50/mo | 500/day |
| **Cost** | Free | $20/mo | $99/mo | $59 (lifetime) | $99/mo | Free |

---

## Testing Your Configuration

### Verify API Keys Work

```bash
# Check what's configured
python main.py --list-api-keys

# Test specific key
python main.py --test-api-key whoisxml

# Run a small scan and check logs
python main.py --start-scan example.com --scan-type passive
tail -f logs/recon.log | grep -i api
```

### Expected Behavior

**With API Keys:**
```
[info] WhoIsXML API configured, running acquisition discovery
[info] Censys API configured, enhanced CT log scanning
[info] Found 1,500 subdomains from multiple sources
```

**Without API Keys:**
```
[warning] WhoIsXML API key not configured, skipping acquisition discovery
[info] Using free CT log sources (crt.sh, bufferover)
[info] Found 1,200 subdomains from free sources
```

Both are perfectly valid! The platform gracefully degrades.

---

## Troubleshooting

### API Key Not Working

1. **Verify key is configured:**
   ```bash
   python main.py --list-api-keys
   ```

2. **Test key directly:**
   ```bash
   python main.py --test-api-key <service>
   ```

3. **Check API quota:**
   - Visit service dashboard
   - Verify you haven't exceeded limits

4. **Try re-adding key:**
   ```bash
   python main.py --remove-api-key <service>
   python main.py --set-api-key <service> <key>
   ```

### Common Errors

| Error | Solution |
|-------|----------|
| `Invalid API key` | Re-generate key from service dashboard |
| `Rate limit exceeded` | Wait for reset or upgrade plan |
| `API key format incorrect` | Check format (e.g., Censys needs `ID:SECRET`) |
| `Service unavailable` | Check service status page |

---

## Summary

### Quick Checklist

- [ ] Platform works **100% without API keys**
- [ ] API keys provide enhanced features (optional)
- [ ] Free tiers available for most services
- [ ] Keys stored encrypted (`config/api_keys.enc`)
- [ ] Use CLI commands for safe management
- [ ] Test keys with `--test-api-key`
- [ ] Monitor usage on service dashboards
- [ ] Rotate keys regularly

### Recommended Setup for Beginners

Start with zero API keys! The platform is fully functional. As you need more:

1. **First:** GitHub token (free, easy)
2. **Second:** VirusTotal (500 req/day free)
3. **Third:** Shodan membership ($59 one-time)
4. **Later:** Consider paid plans based on needs

---

**Questions?** Check our [Tool Installation Guide](TOOL_INSTALLATION.md) or [README](../README.md).

