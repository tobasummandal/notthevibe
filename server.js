#!/usr/bin/env node

import express from 'express';
import VibeSniffScanner from './scan.js';
import VibeSniffVisualizer from './visualizer.js';
import { writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.static('public'));

// CORS middleware
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  next();
});

// Initialize scanner and visualizer
const scanner = new VibeSniffScanner();
const visualizer = new VibeSniffVisualizer();
await scanner.init();

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n🛑 Shutting down server...');
  await scanner.cleanup();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('\n🛑 Shutting down server...');
  await scanner.cleanup();
  process.exit(0);
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    service: 'VibeSniff Lite API',
    version: '1.0.0'
  });
});

// Main scan endpoint
app.get('/scan', async (req, res) => {
  const { url } = req.query;
  
  if (!url) {
    return res.status(400).json({
      error: 'Missing required parameter: url',
      example: '/scan?url=https://example.com'
    });
  }

  // Validate URL
  try {
    new URL(url);
  } catch (error) {
    return res.status(400).json({
      error: 'Invalid URL format',
      provided: url
    });
  }

  try {
    console.log(`🔍 API scan request: ${url}`);
    
    // Generate unique filename for screenshot
    const screenshotId = randomUUID();
    const screenshotPath = `screenshots/${screenshotId}.png`;
    
    // Ensure screenshots directory exists
    try {
      await import('node:fs').then(fs => fs.mkdirSync('screenshots', { recursive: true }));
    } catch (error) {
      // Directory might already exist
    }

    // Temporarily modify the scanner to save screenshot with custom path
    const originalScan = scanner.scan.bind(scanner);
    scanner.scan = async (url) => {
      const page = await scanner.browser.newPage();
      
      try {
        await page.goto(url, { 
          waitUntil: 'networkidle2',
          timeout: 30000 
        });

        await page.screenshot({ 
          path: screenshotPath, 
          fullPage: true 
        });

        const content = await page.content();
        const $ = await import('cheerio').then(cheerio => cheerio.load(content));

        const parsedUrl = new URL(url);
        const domain = parsedUrl.hostname;
        const pageETLD = scanner.getETLDPlusOne(url);

        // Check for password forms
        const passwordInputs = $('input[type="password"]');
        const hasPasswordForm = passwordInputs.length > 0;

        // Check for form action mismatches
        let hasActionMismatch = false;
        if (hasPasswordForm) {
          passwordInputs.each((_, input) => {
            const form = $(input).closest('form');
            const action = form.attr('action');
            if (action) {
              try {
                const actionUrl = new URL(action, url);
                const actionETLD = scanner.getETLDPlusOne(actionUrl.href);
                if (actionETLD && actionETLD !== pageETLD) {
                  hasActionMismatch = true;
                  return false;
                }
              } catch (error) {
                // Invalid action URL, ignore
              }
            }
          });
        }

        // Count external asset hosts
        const externalHosts = new Set();
        
        $('script[src]').each((_, script) => {
          const src = $(script).attr('src');
          if (src) {
            try {
              const srcUrl = new URL(src, url);
              if (srcUrl.hostname !== domain) {
                externalHosts.add(srcUrl.hostname);
              }
            } catch (error) {
              // Invalid URL, ignore
            }
          }
        });

        $('img[src]').each((_, img) => {
          const src = $(img).attr('src');
          if (src) {
            try {
              const srcUrl = new URL(src, url);
              if (srcUrl.hostname !== domain) {
                externalHosts.add(srcUrl.hostname);
              }
            } catch (error) {
              // Invalid URL, ignore
            }
          }
        });

        $('link[href]').each((_, link) => {
          const href = $(link).attr('href');
          if (href) {
            try {
              const hrefUrl = new URL(href, url);
              if (hrefUrl.hostname !== domain) {
                externalHosts.add(hrefUrl.hostname);
              }
            } catch (error) {
              // Invalid URL, ignore
            }
          }
        });

        const externalHostsCount = externalHosts.size;

        // Get domain and TLS ages
        const [domainAge, tlsAge, waybackFirstSeen] = await Promise.all([
          scanner.getDomainAge(domain),
          scanner.getTLSAge(domain),
          scanner.getWaybackFirstSeen(domain)
        ]);

        // Calculate suspiciousness score
        let score = 0;
        const reasons = [];

        if (domainAge !== null && domainAge < 7) {
          score += 0.35;
          reasons.push(`Domain age is ${domainAge} days (suspicious if < 7)`);
        }

        if (tlsAge !== null && tlsAge < 7) {
          score += 0.20;
          reasons.push(`TLS certificate age is ${tlsAge} days (suspicious if < 7)`);
        }

        if (hasPasswordForm) {
          score += 0.20;
          reasons.push('Contains password form');
        }

        if (hasActionMismatch) {
          score += 0.25;
          reasons.push('Password form action points to different domain');
        }

        if (externalHostsCount > 8) {
          score += 0.10;
          reasons.push(`High number of external hosts: ${externalHostsCount} (suspicious if > 8)`);
        }

        score = Math.min(score, 1.0);

        if (reasons.length === 0) {
          reasons.push('No obvious suspicious patterns detected');
        }

        return {
          url,
          score: Math.round(score * 100) / 100,
          reasons,
          domainAgeDays: domainAge,
          tlsAgeDays: tlsAge,
          waybackFirstSeenDays: waybackFirstSeen,
          externalHosts: externalHostsCount,
          externalHostList: Array.from(externalHosts),
          screenshot: `/screenshots/${screenshotId}.png`
        };

      } finally {
        await page.close();
      }
    };

    const result = await scanner.scan(url);
    
    // Restore original scan method
    scanner.scan = originalScan;

    // Generate visualization
    const report = visualizer.generateReport(result);
    result.reportUrl = report.reportUrl;

    res.json(result);

  } catch (error) {
    console.error('❌ Scan failed:', error.message);
    res.status(500).json({
      error: 'Scan failed',
      message: error.message
    });
  }
});

// Serve screenshots and reports
app.use('/screenshots', express.static('screenshots'));
app.use('/reports', express.static('reports'));

// Root endpoint with API documentation
app.get('/', (req, res) => {
  res.json({
    service: 'VibeSniff Lite API',
    version: '1.0.0',
    description: 'Detects suspicious AI-generated scam/phishing websites',
    endpoints: {
      'GET /health': 'Health check',
      'GET /scan?url=<URL>': 'Scan a website for suspicious patterns',
      'GET /screenshots/<id>.png': 'Access screenshot files',
      'GET /reports/report-<id>.html': 'Access interactive reports'
    },
    example: '/scan?url=https://example.com'
  });
});

// Start server
app.listen(port, () => {
  console.log(`🚀 VibeSniff Lite API running on http://localhost:${port}`);
  console.log(`📖 API docs: http://localhost:${port}/`);
  console.log(`🔍 Example: http://localhost:${port}/scan?url=https://example.com`);
});
