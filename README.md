# WP Audit Tool

Comprehensive web security audit tool covering WordPress (WPScan) and Infrastructure (Domain, DNSSEC, SSL, HSTS) with automated Discord notifications.

## Features

- **WordPress Audit** via WPScan: WordPress version, plugins, themes, users, config backups, DB exports
- **Domain Security Audit**: WHOIS, DNSSEC validation, SSL certificates, HSTS policy checks
- **Infrastructure Detection**: Cloudflare proxy detection with accurate IP resolution
- **Vulnerability detection** with severity levels (critical, high, medium, low)
- **Discord report** with rich and colorful embeds (includes specific icons for proxies/security alerts)
- **REST API** with auto-generated Swagger documentation
- **Flexible Execution** — Scans can run synchronously or asynchronously in the background

## Installation

### Docker (recommended)

```bash
# Clone the project
git clone <repo-url>
cd WP_AuditTool

# Configure environment variables
cp .env.example .env
# Edit .env with your Discord webhook and (optional) your WPScan token

# Start with Docker Compose
docker compose up -d

# Or build + run manually
docker build -t wp-audit-tool .
docker run -d -p 8000:8000 --env-file .env --name wp-audit wp-audit-tool
```

The Docker image is based on **Debian Bookworm** and automatically installs:
- Ruby + WPScan via APT/gem
- Python 3 + uv + dependencies

### Local Installation

#### Requirements

- Python 3.11+
- WPScan (`apt/gem install wpscan`)
- [uv](https://docs.astral.sh/uv/) (Python package manager)

#### Setup

```bash
# Clone the project
git clone <repo-url>
cd WP_AuditTool

# Install dependencies
uv sync

# Configure environment variables
cp .env.example .env
# Edit .env with your Discord webhook and (optional) your WPScan token
```

## Configuration

Edit the `.env` file:

| Variable | Description | Required |
|---|---|---|
| `DISCORD_WEBHOOK_URL` | Discord webhook URL | ✅ Yes |
| `WPSCAN_API_TOKEN` | WPScan API Token (for vulnerability details) | ❌ Recommended |
| `WPSCAN_PATH` | Path to the wpscan binary | ❌ Default: `wpscan` |
| `API_HOST` | API Host | ❌ Default: `0.0.0.0` |
| `API_PORT` | API Port | ❌ Default: `8000` |
| `SCAN_TIMEOUT` | Scan timeout in seconds | ❌ Default: `300` |

### Obtain a WPScan token (free)

1. Create an account on [wpscan.com](https://wpscan.com/register)
2. Go to [your profile](https://wpscan.com/profile)
3. Copy your API Token

### Create a Discord webhook

1. Go to **Discord Channel Settings**
2. **Integrations** → **Webhooks**
3. Click on **New Webhook**
4. Copy the webhook URL

## Usage

### Start the API

```bash
uv run uvicorn app.main:app --reload
```

The API will be available at `http://localhost:8000`

### Interactive Documentation

Open `http://localhost:8000/docs` in your browser to access the Swagger UI.

### Run a WordPress audit

```bash
# With Discord webhook configured in .env
curl -X POST http://localhost:8000/audit \
  -H "Content-Type: application/json" \
  -d '{"url": "https://my-wordpress-site.com"}'

# With a custom Discord webhook
curl -X POST http://localhost:8000/audit \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://my-wordpress-site.com",
    "webhook_url": "https://discord.com/api/webhooks/..."
  }'
```

### Run a Domain Security audit

Domain audits perform infrastructure-level security checks, such as SSL/TLS, DNSSEC, and proxy/WAF detection.

```bash
curl -X POST http://localhost:8000/domain-audit \
  -H "Content-Type: application/json" \
  -d '{"domain": "my-wordpress-site.com"}'
```

### Response

```json
{
  "status": "accepted",
  "message": "Audit started for https://my-wordpress-site.com. Results will be sent to Discord.",
  "url": "https://my-wordpress-site.com"
}
```

### Health Check

```bash
curl http://localhost:8000/health
```

## Discord Reports

The Discord report is split into several sections based on the audit type:

### WordPress Audit Embeds
| Embed | Description |
|---|---|
| 🔍 **Main Report** | URL, WordPress version, server, active theme, security score |
| ⚠️ **Vulnerabilities** | List of CVEs with severity and links |
| 🔌 **Plugins** | Detected plugins with versions and status |
| 🎨 **Themes** | Detected themes with versions |
| 👤 **Users** | Enumerated WordPress users |
| 📁 **Sensitive Files** | Config backups, DB exports, TimThumbs |
| 🔎 **Findings** | Interesting headers and exposed files |
| 📊 **Statistics** | Duration, requests, transferred data |

### Domain Security Audit Embeds
| Embed | Description |
|---|---|
| 🌐 **Domain Info** | WHOIS data, creation/expiration dates, registrar |
| 🛡️ **DNS & Infrastructure** | DNS Records, DNSSEC status, Cloudflare proxy detection |
| 🔒 **Security Headers** | SSL/TLS certificates, HSTS caching duration |

## ⚠️ Warning

This tool should only be used on **your own WordPress sites** or with **explicit permission** from the owner. Unauthorized use of this tool may be illegal.

## License

Internal use only.
