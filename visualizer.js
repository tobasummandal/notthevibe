#!/usr/bin/env node

import { writeFileSync, mkdirSync } from 'node:fs';
import { randomUUID } from 'node:crypto';

/**
 * VibeSniff Lite Visualizer - Generates interactive HTML reports
 */

class VibeSniffVisualizer {
  constructor() {
    this.reportsDir = 'reports';
    this.ensureReportsDir();
  }

  ensureReportsDir() {
    try {
      mkdirSync(this.reportsDir, { recursive: true });
    } catch (error) {
      // Directory might already exist
    }
  }

  generateReport(scanResult) {
    const reportId = randomUUID();
    const reportPath = `${this.reportsDir}/report-${reportId}.html`;
    
    const html = this.generateHTML(scanResult, reportId);
    writeFileSync(reportPath, html);
    
    return {
      reportId,
      reportPath,
      reportUrl: `/reports/report-${reportId}.html`
    };
  }

  generateHTML(scanResult, reportId) {
    const riskColor = this.getRiskColor(scanResult.riskLevel);
    const scorePercentage = Math.round(scanResult.score * 100);
    
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VibeSniff Report - ${scanResult.technical.domain}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            background: white; 
            border-radius: 20px; 
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header { 
            background: linear-gradient(135deg, #${riskColor} 0%, #${this.darkenColor(riskColor, 20)} 100%);
            color: white; 
            padding: 40px; 
            text-align: center;
        }
        .risk-badge {
            display: inline-block;
            background: rgba(255,255,255,0.2);
            padding: 10px 20px;
            border-radius: 25px;
            font-size: 18px;
            font-weight: bold;
            margin: 10px 0;
        }
        .score-circle {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            background: conic-gradient(#${riskColor} 0deg, #${riskColor} ${scorePercentage * 3.6}deg, #e0e0e0 ${scorePercentage * 3.6}deg, #e0e0e0 360deg);
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 20px auto;
            position: relative;
        }
        .score-circle::before {
            content: '';
            width: 80px;
            height: 80px;
            background: white;
            border-radius: 50%;
            position: absolute;
        }
        .score-text {
            font-size: 24px;
            font-weight: bold;
            color: #${riskColor};
            z-index: 1;
        }
        .content { padding: 40px; }
        .grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); 
            gap: 30px; 
            margin: 30px 0;
        }
        .card { 
            background: #f8f9fa; 
            padding: 25px; 
            border-radius: 15px; 
            border-left: 5px solid #${riskColor};
        }
        .card h3 { 
            color: #${riskColor}; 
            margin-bottom: 15px; 
            font-size: 18px;
        }
        .metric { 
            display: flex; 
            justify-content: space-between; 
            margin: 10px 0; 
            padding: 8px 0;
            border-bottom: 1px solid #e0e0e0;
        }
        .metric:last-child { border-bottom: none; }
        .metric-label { font-weight: 500; color: #666; }
        .metric-value { font-weight: bold; color: #333; }
        .reasons { 
            background: #fff3cd; 
            border: 1px solid #ffeaa7; 
            border-radius: 10px; 
            padding: 20px; 
            margin: 20px 0;
        }
        .reasons h4 { color: #856404; margin-bottom: 15px; }
        .reasons ul { list-style: none; }
        .reasons li { 
            padding: 8px 0; 
            border-bottom: 1px solid #ffeaa7; 
            color: #856404;
        }
        .reasons li:last-child { border-bottom: none; }
        .chart-container { 
            background: white; 
            padding: 20px; 
            border-radius: 15px; 
            margin: 20px 0;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
        }
        .footer { 
            background: #f8f9fa; 
            padding: 20px; 
            text-align: center; 
            color: #666;
            border-top: 1px solid #e0e0e0;
        }
        .suspicious { color: #dc3545; font-weight: bold; }
        .warning { color: #ffc107; font-weight: bold; }
        .safe { color: #28a745; font-weight: bold; }
        .code { 
            background: #f1f3f4; 
            padding: 2px 6px; 
            border-radius: 4px; 
            font-family: 'Monaco', 'Menlo', monospace; 
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 VibeSniff Lite Report</h1>
            <div class="risk-badge">Risk Level: ${scanResult.riskLevel}</div>
            <div class="score-circle">
                <div class="score-text">${scorePercentage}%</div>
            </div>
            <h2>${scanResult.technical.domain}</h2>
            <p class="code">${scanResult.url}</p>
        </div>

        <div class="content">
            ${this.generateReasonsSection(scanResult)}
            
            <div class="grid">
                ${this.generateDomainCard(scanResult)}
                ${this.generateContentCard(scanResult)}
                ${this.generateFormsCard(scanResult)}
                ${this.generateLinksCard(scanResult)}
                ${this.generateTechnicalCard(scanResult)}
                ${this.generateResourcesCard(scanResult)}
            </div>

            ${this.generateChartsSection(scanResult)}
        </div>

        <div class="footer">
            <p>Generated by VibeSniff Lite on ${new Date(scanResult.scannedAt).toLocaleString()}</p>
            <p>Report ID: ${reportId}</p>
        </div>
    </div>

    <script>
        // Risk factors chart
        const riskCtx = document.getElementById('riskChart');
        if (riskCtx) {
            new Chart(riskCtx, {
                type: 'doughnut',
                data: {
                    labels: ${JSON.stringify(scanResult.riskFactors.map(f => f.factor))},
                    datasets: [{
                        data: ${JSON.stringify(scanResult.riskFactors.map(f => f.weight))},
                        backgroundColor: [
                            '#ff6384', '#36a2eb', '#ffce56', '#4bc0c0', 
                            '#9966ff', '#ff9f40', '#ff6384', '#c9cbcf'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: { position: 'bottom' }
                    }
                }
            });
        }

        // External hosts chart
        const hostsCtx = document.getElementById('hostsChart');
        if (hostsCtx) {
            new Chart(hostsCtx, {
                type: 'bar',
                data: {
                    labels: ['External Hosts', 'Internal Resources'],
                    datasets: [{
                        label: 'Resource Count',
                        data: [${scanResult.externalHosts}, ${Math.max(1, 10 - scanResult.externalHosts)}],
                        backgroundColor: ['#ff6384', '#36a2eb']
                    }]
                },
                options: {
                    responsive: true,
                    scales: { y: { beginAtZero: true } }
                }
            });
        }
    </script>
</body>
</html>`;
  }

  generateReasonsSection(scanResult) {
    if (scanResult.reasons.length === 0) return '';
    
    return `
    <div class="reasons">
        <h4>🚨 Security Analysis Results</h4>
        <ul>
            ${scanResult.reasons.map(reason => `<li>${reason}</li>`).join('')}
        </ul>
    </div>`;
  }

  generateDomainCard(scanResult) {
    return `
    <div class="card">
        <h3>🌐 Domain Information</h3>
        <div class="metric">
            <span class="metric-label">Domain Age</span>
            <span class="metric-value ${this.getAgeClass(scanResult.domainAgeDays)}">
                ${scanResult.domainAgeDays ? `${scanResult.domainAgeDays} days` : 'Unknown'}
            </span>
        </div>
        <div class="metric">
            <span class="metric-label">TLS Certificate Age</span>
            <span class="metric-value ${this.getAgeClass(scanResult.tlsAgeDays)}">
                ${scanResult.tlsAgeDays ? `${scanResult.tlsAgeDays} days` : 'Unknown'}
            </span>
        </div>
        <div class="metric">
            <span class="metric-label">Wayback First Seen</span>
            <span class="metric-value">
                ${scanResult.waybackFirstSeenDays ? `${scanResult.waybackFirstSeenDays} days ago` : 'Unknown'}
            </span>
        </div>
        <div class="metric">
            <span class="metric-label">Protocol</span>
            <span class="metric-value">${scanResult.technical.protocol}</span>
        </div>
    </div>`;
  }

  generateContentCard(scanResult) {
    return `
    <div class="card">
        <h3>📄 Content Analysis</h3>
        <div class="metric">
            <span class="metric-label">Page Title</span>
            <span class="metric-value">${scanResult.content.title || 'No title'}</span>
        </div>
        <div class="metric">
            <span class="metric-label">Total Headings</span>
            <span class="metric-value">${scanResult.content.totalHeadings}</span>
        </div>
        <div class="metric">
            <span class="metric-label">Suspicious Keywords</span>
            <span class="metric-value ${scanResult.content.suspiciousKeywords.length > 3 ? 'suspicious' : 'safe'}">
                ${scanResult.content.suspiciousKeywords.length}
            </span>
        </div>
        <div class="metric">
            <span class="metric-label">Has Popups/Redirects</span>
            <span class="metric-value ${scanResult.content.hasPopups || scanResult.content.hasRedirects ? 'suspicious' : 'safe'}">
                ${scanResult.content.hasPopups || scanResult.content.hasRedirects ? 'Yes' : 'No'}
            </span>
        </div>
    </div>`;
  }

  generateFormsCard(scanResult) {
    return `
    <div class="card">
        <h3>📝 Form Analysis</h3>
        <div class="metric">
            <span class="metric-label">Total Forms</span>
            <span class="metric-value">${scanResult.forms.totalForms}</span>
        </div>
        <div class="metric">
            <span class="metric-label">Password Inputs</span>
            <span class="metric-value ${scanResult.forms.hasPasswordForm ? 'suspicious' : 'safe'}">
                ${scanResult.forms.passwordInputs}
            </span>
        </div>
        <div class="metric">
            <span class="metric-label">Email Inputs</span>
            <span class="metric-value">${scanResult.forms.emailInputs}</span>
        </div>
        <div class="metric">
            <span class="metric-label">Suspicious Actions</span>
            <span class="metric-value ${scanResult.forms.suspiciousActions.length > 0 ? 'suspicious' : 'safe'}">
                ${scanResult.forms.suspiciousActions.length}
            </span>
        </div>
    </div>`;
  }

  generateLinksCard(scanResult) {
    return `
    <div class="card">
        <h3>🔗 Link Analysis</h3>
        <div class="metric">
            <span class="metric-label">Total Links</span>
            <span class="metric-value">${scanResult.links.totalLinks}</span>
        </div>
        <div class="metric">
            <span class="metric-label">External Links</span>
            <span class="metric-value">${scanResult.links.externalLinks}</span>
        </div>
        <div class="metric">
            <span class="metric-label">Suspicious Link Patterns</span>
            <span class="metric-value ${scanResult.links.suspiciousLinkPatterns.length > 0 ? 'suspicious' : 'safe'}">
                ${scanResult.links.suspiciousLinkPatterns.length}
            </span>
        </div>
    </div>`;
  }

  generateTechnicalCard(scanResult) {
    return `
    <div class="card">
        <h3>⚙️ Technical Details</h3>
        <div class="metric">
            <span class="metric-label">Domain</span>
            <span class="metric-value">${scanResult.technical.domain}</span>
        </div>
        <div class="metric">
            <span class="metric-label">eTLD+1</span>
            <span class="metric-value">${scanResult.technical.pageETLD}</span>
        </div>
        <div class="metric">
            <span class="metric-label">Port</span>
            <span class="metric-value">${scanResult.technical.port}</span>
        </div>
        <div class="metric">
            <span class="metric-label">Path</span>
            <span class="metric-value">${scanResult.technical.pathname}</span>
        </div>
    </div>`;
  }

  generateResourcesCard(scanResult) {
    return `
    <div class="card">
        <h3>📦 Resource Analysis</h3>
        <div class="metric">
            <span class="metric-label">External Hosts</span>
            <span class="metric-value ${scanResult.externalHosts > 8 ? 'suspicious' : 'safe'}">
                ${scanResult.externalHosts}
            </span>
        </div>
        <div class="metric">
            <span class="metric-label">Iframes</span>
            <span class="metric-value">${scanResult.iframes.totalIframes}</span>
        </div>
        <div class="metric">
            <span class="metric-label">Suspicious Iframes</span>
            <span class="metric-value ${scanResult.iframes.suspiciousIframes > 0 ? 'suspicious' : 'safe'}">
                ${scanResult.iframes.suspiciousIframes}
            </span>
        </div>
    </div>`;
  }

  generateChartsSection(scanResult) {
    return `
    <div class="chart-container">
        <h3>📊 Risk Analysis</h3>
        <canvas id="riskChart" width="400" height="200"></canvas>
    </div>
    
    <div class="chart-container">
        <h3>📈 Resource Distribution</h3>
        <canvas id="hostsChart" width="400" height="200"></canvas>
    </div>`;
  }

  getRiskColor(riskLevel) {
    switch (riskLevel) {
      case 'HIGH': return 'dc3545';
      case 'MEDIUM': return 'ffc107';
      case 'LOW': return '28a745';
      default: return '6c757d';
    }
  }

  getAgeClass(age) {
    if (age === null) return 'warning';
    if (age < 7) return 'suspicious';
    if (age < 30) return 'warning';
    return 'safe';
  }

  darkenColor(color, percent) {
    const num = parseInt(color, 16);
    const amt = Math.round(2.55 * percent);
    const R = (num >> 16) - amt;
    const G = (num >> 8 & 0x00FF) - amt;
    const B = (num & 0x0000FF) - amt;
    return (0x1000000 + (R < 255 ? R < 1 ? 0 : R : 255) * 0x10000 +
            (G < 255 ? G < 1 ? 0 : G : 255) * 0x100 +
            (B < 255 ? B < 1 ? 0 : B : 255)).toString(16).slice(1);
  }
}

export default VibeSniffVisualizer;
