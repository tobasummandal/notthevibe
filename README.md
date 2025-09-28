# NotTheVibe Lite 🔍

A comprehensive security analysis tool that detects suspicious AI-generated scam/phishing websites through advanced pattern recognition and behavioral analysis.

[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Puppeteer](https://img.shields.io/badge/Puppeteer-21.5.2-orange.svg)](https://pptr.dev/)
[![Chart.js](https://img.shields.io/badge/Chart.js-4.4.0-red.svg)](https://www.chartjs.org/)

## 🎬 Quick Demo

```bash
# Clone and run
git clone <your-repo>
cd vibesniff-lite
npm install
npm run demo

# Or scan any website
node scan.js https://github.com
```

**Output:** Interactive HTML report with risk analysis, charts, and full-page screenshot! 📊

## 🚀 Features

### Core Analysis
- **Full-page screenshots** using Puppeteer
- **Advanced DOM analysis** with Cheerio for comprehensive form and content detection
- **Domain age checking** via WHOIS lookup with Wayback Machine integration
- **TLS certificate age** analysis and validation
- **External asset host counting** (scripts, images, links, iframes)
- **Content analysis** with suspicious keyword detection
- **Link analysis** with external link tracking and pattern detection

### Enhanced Detection
- **Form analysis** - Password forms, action mismatches, suspicious patterns
- **Popup/redirect detection** - JavaScript-based redirection analysis
- **Iframe analysis** - Suspicious embedded content detection
- **Risk categorization** - LOW/MEDIUM/HIGH risk levels
- **Comprehensive scoring** - Multi-factor suspiciousness scoring (0.0-1.0)

### Visualization & Reporting
- **Interactive HTML reports** with charts and visualizations
- **Real-time risk assessment** with detailed breakdowns
- **Chart.js integration** for data visualization
- **Responsive design** for all devices
- **Export capabilities** for screenshots and reports

### API & Integration
- **REST API** for Chrome extension integration
- **CLI interface** for quick scans
- **JSON output** with comprehensive data
- **CORS enabled** for web integration

## 🚀 Quick Start

### 1. Install Dependencies

```bash
npm install
```

### 2. CLI Usage (Recommended)

Scan any website with comprehensive analysis:

```bash
# Basic scan
npm run scan -- https://example.com

# Direct usage
node scan.js https://github.com

# Demo with automatic report opening
npm run demo
```

**What you get:**
- 📊 **Comprehensive JSON output** with 50+ data points
- 📸 **Full-page screenshot** saved as `out.png`
- 📈 **Interactive HTML report** in `reports/` directory
- 🎯 **Risk assessment** with detailed breakdown
- 📱 **Responsive visualization** with charts and graphs

### 3. API Server (Optional)

Start the REST API server for integration:

```bash
npm run server
```

**Available Endpoints:**
- `GET /health` - Health check
- `GET /scan?url=<URL>` - Scan a website
- `GET /screenshots/<id>.png` - Access screenshot files
- `GET /reports/report-<id>.html` - Access interactive reports

**Example API usage:**
```bash
curl "http://localhost:3000/scan?url=https://example.com"
```

**Note:** The API includes a `reportUrl` field for easy access to interactive reports.

## 🎯 Enhanced Scoring System

The tool calculates a comprehensive suspiciousness score (0.0 to 1.0) based on multiple risk factors:

### Domain & Certificate Analysis
| Indicator | Weight | Description |
|-----------|--------|-------------|
| Domain age < 7 days | +0.35 | New domains are highly suspicious |
| Domain age < 30 days | +0.15 | Recent domains are somewhat suspicious |
| TLS age < 7 days | +0.20 | New certificates are suspicious |

### Form & Input Analysis
| Indicator | Weight | Description |
|-----------|--------|-------------|
| Password form present | +0.20 | Indicates potential phishing |
| Form action mismatch | +0.25 | Action points to different domain |
| Suspicious form patterns | +0.15 | GET method with passwords, etc. |

### Content & Behavior Analysis
| Indicator | Weight | Description |
|-----------|--------|-------------|
| Suspicious keywords > 3 | +0.15 | High number of phishing-related terms |
| Suspicious link patterns | +0.10 | "Click here", "Verify now" links |
| Popup/redirect scripts | +0.10 | JavaScript-based redirections |
| Suspicious iframes | +0.10 | Embedded content from external domains |

### Resource Analysis
| Indicator | Weight | Description |
|-----------|--------|-------------|
| External hosts > 8 | +0.10 | High number of external resources |

### Risk Levels
- **LOW** (0.0-0.4): Minimal suspicious indicators
- **MEDIUM** (0.4-0.7): Multiple concerning patterns
- **HIGH** (0.7-1.0): Highly suspicious, likely malicious

## 📊 Enhanced Output Format

The tool now provides comprehensive analysis data:

```json
{
  "url": "https://example.com",
  "score": 0.45,
  "riskLevel": "MEDIUM",
  "reasons": [
    "Domain age is 3 days (suspicious if < 7)",
    "Contains password form",
    "High number of suspicious keywords: 5"
  ],
  "riskFactors": [
    { "factor": "New Domain", "weight": 0.35, "value": 3 },
    { "factor": "Password Form", "weight": 0.20, "value": 1 },
    { "factor": "Suspicious Keywords", "weight": 0.15, "value": 5 }
  ],
  "domainAgeDays": 3,
  "tlsAgeDays": 5,
  "waybackFirstSeenDays": 2,
  "externalHosts": 12,
  "externalHostList": ["cdn.example.com", "analytics.google.com"],
  "content": {
    "title": "Example Site",
    "metaDescription": "A sample website",
    "totalHeadings": 8,
    "suspiciousKeywords": ["urgent", "verify", "account"],
    "hasPopups": false,
    "hasRedirects": true
  },
  "forms": {
    "totalForms": 2,
    "hasPasswordForm": true,
    "passwordInputs": 1,
    "suspiciousActions": ["https://different-domain.com/login"]
  },
  "links": {
    "totalLinks": 15,
    "externalLinks": 8,
    "suspiciousLinkPatterns": ["Suspicious link text: \"Click here\""]
  },
  "technical": {
    "domain": "example.com",
    "protocol": "https:",
    "port": "443"
  },
  "scannedAt": "2025-09-28T03:10:51.408Z",
  "reportUrl": "/reports/report-abc123.html"
}
```

## 📋 Requirements

- **Node.js 18+** (LTS recommended)
- **Modern OS** (macOS, Linux, Windows)
- **Internet connection** (for WHOIS, TLS, and Wayback Machine checks)
- **4GB+ RAM** (for Puppeteer browser automation)

## 📦 Dependencies

| Package | Purpose | Version |
|---------|---------|---------|
| **puppeteer** | Headless Chrome automation | ^21.5.2 |
| **cheerio** | Server-side jQuery for DOM parsing | ^1.0.0-rc.12 |
| **whois-json** | Domain WHOIS lookups | ^2.0.0 |
| **express** | REST API server | ^4.18.2 |
| **chart.js** | Interactive data visualization | ^4.4.0 |
| **canvas** | Server-side image generation | ^2.11.2 |

## 🛡️ Error Handling

The tool gracefully handles failures with fallback values:
- **WHOIS lookup failures** → `domainAgeDays: null`
- **TLS certificate errors** → `tlsAgeDays: null`
- **Wayback Machine errors** → `waybackFirstSeenDays: null`
- **Network timeouts** → Error message with fallback
- **Invalid URLs** → Clear error messages
- **Browser crashes** → Automatic cleanup and retry

## 🎯 Use Cases

### Security & Research
- **Security researchers** analyzing suspicious websites
- **Threat intelligence** gathering and analysis
- **Phishing campaign** detection and tracking
- **Educational purposes** for understanding web security

### Integration & Automation
- **Chrome extension** integration for real-time scanning
- **Automated monitoring** of known phishing patterns
- **API integration** with security tools and platforms
- **Batch processing** of multiple URLs

### Visualization & Reporting
- **Interactive reports** for security teams
- **Data visualization** for risk assessment
- **Export capabilities** for documentation
- **Real-time dashboards** for monitoring

## ⚠️ Limitations

- **Internet dependency** - Requires connection for WHOIS, TLS, and Wayback Machine checks
- **Anti-bot measures** - Some websites may block automated access
- **Heuristic scoring** - May produce false positives/negatives
- **Dynamic content** - Screenshots may not capture all dynamic elements
- **Rate limiting** - Some APIs (WHOIS, Wayback) may have rate limits
- **Browser resources** - Puppeteer requires significant memory for complex sites

## 🛠️ Development

The project uses modern ES modules (`type: "module"` in package.json) and requires Node.js 18+.

### Project Structure

```
vibesniff-lite/
├── scan.js              # Core scanner (CLI)
├── server.js            # Express API server  
├── visualizer.js        # HTML report generator
├── package.json         # Dependencies and scripts
├── README.md            # This file
├── .gitignore           # Git ignore rules
├── reports/             # Generated HTML reports
│   └── report-*.html    # Interactive visualizations
├── screenshots/         # Generated screenshots
│   └── *.png           # Full-page screenshots
└── out.png             # Latest CLI screenshot
```

### Available Scripts

```bash
npm run scan -- <URL>    # Scan a website
npm run server           # Start API server
npm run test             # Test with example.com
npm run demo             # Demo with GitHub + open report
```

## 🏆 Hackathon Ready

This project is **perfect for security hackathons** and demonstrates:
- ✅ **Advanced web scraping** with Puppeteer
- ✅ **DOM analysis** with Cheerio  
- ✅ **Data visualization** with Chart.js
- ✅ **REST API design** with Express
- ✅ **Comprehensive security analysis**
- ✅ **Interactive reporting**
- ✅ **Production-ready code**

## 📄 License

MIT License - feel free to use and modify for your projects.

---

**⚠️ Disclaimer**: This tool is for educational and research purposes. Always verify suspicious websites through multiple sources and official channels.
