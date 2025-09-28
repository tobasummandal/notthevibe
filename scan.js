#!/usr/bin/env node

import puppeteer from 'puppeteer';
import * as cheerio from 'cheerio';
import whois from 'whois-json';
import { connect } from 'node:tls';
import { URL } from 'node:url';
import { writeFileSync } from 'node:fs';
import VibeSniffVisualizer from './visualizer.js';

/**
 * VibeSniff Lite - Detects suspicious AI-generated scam/phishing websites
 */

class VibeSniffScanner {
  constructor() {
    this.browser = null;
    this.visualizer = new VibeSniffVisualizer();
  }

  async init() {
    this.browser = await puppeteer.launch({
      headless: 'new',
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
  }

  async cleanup() {
    if (this.browser) {
      await this.browser.close();
    }
  }

  /**
   * Extract eTLD+1 from a URL
   */
  getETLDPlusOne(url) {
    try {
      const parsed = new URL(url);
      const hostname = parsed.hostname;
      const parts = hostname.split('.');
      if (parts.length >= 2) {
        return parts.slice(-2).join('.');
      }
      return hostname;
    } catch (error) {
      return null;
    }
  }

  /**
   * Get domain age in days using WHOIS
   */
  async getDomainAge(domain) {
    try {
      const result = await whois(domain);
      const creationDate = result.creationDate || result.registered || result.created;
      
      if (creationDate) {
        const created = new Date(creationDate);
        const now = new Date();
        const diffTime = Math.abs(now - created);
        return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
      }
    } catch (error) {
      console.error(`WHOIS lookup failed for ${domain}:`, error.message);
    }
    return null;
  }

  /**
   * Get TLS certificate age in days
   */
  async getTLSAge(hostname, port = 443) {
    return new Promise((resolve) => {
      try {
        const socket = connect(port, hostname, () => {
          const cert = socket.getPeerCertificate();
          if (cert && cert.valid_from) {
            const validFrom = new Date(cert.valid_from);
            const now = new Date();
            const diffTime = Math.abs(now - validFrom);
            const ageInDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
            resolve(ageInDays);
          } else {
            resolve(null);
          }
          socket.end();
        });

        socket.on('error', (error) => {
          console.error(`TLS check failed for ${hostname}:`, error.message);
          resolve(null);
        });

        socket.setTimeout(5000, () => {
          socket.destroy();
          resolve(null);
        });
      } catch (error) {
        console.error(`TLS check failed for ${hostname}:`, error.message);
        resolve(null);
      }
    });
  }

  /**
   * Query Wayback Machine for earliest snapshot
   */
  async getWaybackFirstSeen(domain) {
    try {
      const response = await fetch(`http://web.archive.org/cdx/search/cdx?url=${domain}&output=json&limit=1&sort=timestamp:asc`);
      const data = await response.json();
      
      if (data && data.length > 1 && data[1][1]) {
        const timestamp = data[1][1];
        const firstSeen = new Date(timestamp.substring(0, 4) + '-' + 
                                 timestamp.substring(4, 6) + '-' + 
                                 timestamp.substring(6, 8));
        const now = new Date();
        const diffTime = Math.abs(now - firstSeen);
        return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
      }
    } catch (error) {
      console.error(`Wayback Machine check failed for ${domain}:`, error.message);
    }
    return null;
  }

  /**
   * Scan a website for suspicious patterns
   */
  async scan(url) {
    if (!this.browser) {
      await this.init();
    }

    const page = await this.browser.newPage();
    
    try {
      // Navigate to the page
      await page.goto(url, { 
        waitUntil: 'networkidle2',
        timeout: 30000 
      });

      // Take screenshot
      await page.screenshot({ 
        path: 'out.png', 
        fullPage: true 
      });

      // Get page content
      const content = await page.content();
      const $ = cheerio.load(content);

      // Parse URL
      const parsedUrl = new URL(url);
      const domain = parsedUrl.hostname;
      const pageETLD = this.getETLDPlusOne(url);

      // Enhanced form analysis
      const passwordInputs = $('input[type="password"]');
      const emailInputs = $('input[type="email"]');
      const textInputs = $('input[type="text"]');
      const allInputs = $('input');
      const forms = $('form');
      
      const hasPasswordForm = passwordInputs.length > 0;
      const hasEmailForm = emailInputs.length > 0;
      const hasTextInputs = textInputs.length > 0;
      const totalInputs = allInputs.length;
      const totalForms = forms.length;

      // Check for form action mismatches
      let hasActionMismatch = false;
      let suspiciousActions = [];
      if (hasPasswordForm) {
        passwordInputs.each((_, input) => {
          const form = $(input).closest('form');
          const action = form.attr('action');
          if (action) {
            try {
              const actionUrl = new URL(action, url);
              const actionETLD = this.getETLDPlusOne(actionUrl.href);
              if (actionETLD && actionETLD !== pageETLD) {
                hasActionMismatch = true;
                suspiciousActions.push(actionUrl.href);
                return false; // break
              }
            } catch (error) {
              // Invalid action URL, ignore
            }
          }
        });
      }

      // Check for suspicious form patterns
      let suspiciousFormPatterns = [];
      forms.each((_, form) => {
        const $form = $(form);
        const method = $form.attr('method') || 'get';
        const action = $form.attr('action') || '';
        
        // Check for suspicious form attributes
        if (method.toLowerCase() === 'get' && hasPasswordForm) {
          suspiciousFormPatterns.push('Password form uses GET method');
        }
        
        if (action.includes('javascript:') || action.includes('data:')) {
          suspiciousFormPatterns.push('Suspicious form action detected');
        }
      });

      // Count external asset hosts
      const externalHosts = new Set();
      
      // Check script sources
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

      // Check image sources
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

      // Check link sources
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

      // Enhanced content analysis
      const title = $('title').text().trim();
      const metaDescription = $('meta[name="description"]').attr('content') || '';
      const metaKeywords = $('meta[name="keywords"]').attr('content') || '';
      const h1Tags = $('h1').length;
      const h2Tags = $('h2').length;
      const h3Tags = $('h3').length;
      const totalHeadings = h1Tags + h2Tags + h3Tags;
      
      // Check for suspicious content patterns
      const suspiciousKeywords = [
        'urgent', 'verify', 'confirm', 'update', 'suspended', 'expired',
        'security', 'account', 'login', 'password', 'credit card', 'ssn',
        'social security', 'banking', 'paypal', 'amazon', 'apple', 'microsoft'
      ];
      
      const pageText = $('body').text().toLowerCase();
      const foundSuspiciousKeywords = suspiciousKeywords.filter(keyword => 
        pageText.includes(keyword.toLowerCase())
      );
      
      // Check for suspicious links
      const allLinks = $('a[href]');
      const externalLinks = [];
      const suspiciousLinkPatterns = [];
      
      allLinks.each((_, link) => {
        const href = $(link).attr('href');
        const linkText = $(link).text().trim();
        
        if (href) {
          try {
            const linkUrl = new URL(href, url);
            if (linkUrl.hostname !== domain) {
              externalLinks.push({
                url: linkUrl.href,
                text: linkText,
                isExternal: true
              });
              
              // Check for suspicious link patterns
              if (linkText.toLowerCase().includes('click here') || 
                  linkText.toLowerCase().includes('verify now') ||
                  linkText.toLowerCase().includes('update now')) {
                suspiciousLinkPatterns.push(`Suspicious link text: "${linkText}"`);
              }
            }
          } catch (error) {
            // Invalid URL, ignore
          }
        }
      });

      // Check for popup/redirect patterns
      const hasPopups = $('script').text().includes('window.open') || 
                       $('script').text().includes('popup');
      const hasRedirects = $('script').text().includes('window.location') ||
                          $('script').text().includes('document.location');
      
      // Check for iframe usage
      const iframes = $('iframe').length;
      const suspiciousIframes = [];
      $('iframe').each((_, iframe) => {
        const src = $(iframe).attr('src');
        if (src) {
          try {
            const iframeUrl = new URL(src, url);
            if (iframeUrl.hostname !== domain) {
              suspiciousIframes.push(iframeUrl.href);
            }
          } catch (error) {
            // Invalid URL, ignore
          }
        }
      });

      // Get domain and TLS ages
      const [domainAge, tlsAge, waybackFirstSeen] = await Promise.all([
        this.getDomainAge(domain),
        this.getTLSAge(domain),
        this.getWaybackFirstSeen(domain)
      ]);

      // Enhanced scoring system
      let score = 0;
      const reasons = [];
      const riskFactors = [];

      // Domain age analysis
      if (domainAge !== null && domainAge < 7) {
        score += 0.35;
        reasons.push(`Domain age is ${domainAge} days (suspicious if < 7)`);
        riskFactors.push({ factor: 'New Domain', weight: 0.35, value: domainAge });
      } else if (domainAge !== null && domainAge < 30) {
        score += 0.15;
        reasons.push(`Domain age is ${domainAge} days (somewhat new)`);
        riskFactors.push({ factor: 'Recent Domain', weight: 0.15, value: domainAge });
      }

      // TLS certificate analysis
      if (tlsAge !== null && tlsAge < 7) {
        score += 0.20;
        reasons.push(`TLS certificate age is ${tlsAge} days (suspicious if < 7)`);
        riskFactors.push({ factor: 'New Certificate', weight: 0.20, value: tlsAge });
      }

      // Form analysis
      if (hasPasswordForm) {
        score += 0.20;
        reasons.push('Contains password form');
        riskFactors.push({ factor: 'Password Form', weight: 0.20, value: 1 });
      }

      if (hasActionMismatch) {
        score += 0.25;
        reasons.push('Password form action points to different domain');
        riskFactors.push({ factor: 'Action Mismatch', weight: 0.25, value: 1 });
      }

      if (suspiciousFormPatterns.length > 0) {
        score += 0.15;
        reasons.push(`Suspicious form patterns: ${suspiciousFormPatterns.join(', ')}`);
        riskFactors.push({ factor: 'Suspicious Forms', weight: 0.15, value: suspiciousFormPatterns.length });
      }

      // External resources analysis
      if (externalHostsCount > 8) {
        score += 0.10;
        reasons.push(`High number of external hosts: ${externalHostsCount} (suspicious if > 8)`);
        riskFactors.push({ factor: 'High External Hosts', weight: 0.10, value: externalHostsCount });
      }

      // Content analysis
      if (foundSuspiciousKeywords.length > 3) {
        score += 0.15;
        reasons.push(`High number of suspicious keywords: ${foundSuspiciousKeywords.length}`);
        riskFactors.push({ factor: 'Suspicious Keywords', weight: 0.15, value: foundSuspiciousKeywords.length });
      }

      if (suspiciousLinkPatterns.length > 0) {
        score += 0.10;
        reasons.push(`Suspicious link patterns detected: ${suspiciousLinkPatterns.length}`);
        riskFactors.push({ factor: 'Suspicious Links', weight: 0.10, value: suspiciousLinkPatterns.length });
      }

      if (hasPopups || hasRedirects) {
        score += 0.10;
        reasons.push('Contains popup or redirect scripts');
        riskFactors.push({ factor: 'Popups/Redirects', weight: 0.10, value: 1 });
      }

      if (suspiciousIframes.length > 0) {
        score += 0.10;
        reasons.push(`Suspicious iframes detected: ${suspiciousIframes.length}`);
        riskFactors.push({ factor: 'Suspicious Iframes', weight: 0.10, value: suspiciousIframes.length });
      }

      // Cap score at 1.0
      score = Math.min(score, 1.0);

      // Determine risk level
      let riskLevel = 'LOW';
      if (score > 0.7) riskLevel = 'HIGH';
      else if (score > 0.4) riskLevel = 'MEDIUM';

      // If no suspicious indicators, add a reason
      if (reasons.length === 0) {
        reasons.push('No obvious suspicious patterns detected');
      }

      return {
        url,
        score: Math.round(score * 100) / 100,
        riskLevel,
        reasons,
        riskFactors,
        
        // Domain information
        domainAgeDays: domainAge,
        tlsAgeDays: tlsAge,
        waybackFirstSeenDays: waybackFirstSeen,
        
        // Resource analysis
        externalHosts: externalHostsCount,
        externalHostList: Array.from(externalHosts),
        
        // Content analysis
        content: {
          title,
          metaDescription,
          metaKeywords,
          totalHeadings,
          h1Tags,
          h2Tags,
          h3Tags,
          suspiciousKeywords: foundSuspiciousKeywords,
          suspiciousLinkPatterns,
          hasPopups,
          hasRedirects
        },
        
        // Form analysis
        forms: {
          totalForms,
          totalInputs,
          hasPasswordForm,
          hasEmailForm,
          hasTextInputs,
          passwordInputs: passwordInputs.length,
          emailInputs: emailInputs.length,
          textInputs: textInputs.length,
          suspiciousActions,
          suspiciousFormPatterns
        },
        
        // Link analysis
        links: {
          totalLinks: allLinks.length,
          externalLinks: externalLinks.length,
          externalLinkList: externalLinks.slice(0, 10), // Limit to first 10
          suspiciousLinkPatterns
        },
        
        // Iframe analysis
        iframes: {
          totalIframes: iframes,
          suspiciousIframes: suspiciousIframes.length,
          suspiciousIframeList: suspiciousIframes
        },
        
        // Technical details
        technical: {
          domain,
          pageETLD,
          protocol: parsedUrl.protocol,
          port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? '443' : '80'),
          pathname: parsedUrl.pathname,
          search: parsedUrl.search,
          hash: parsedUrl.hash
        },
        
        // Timestamps
        scannedAt: new Date().toISOString(),
        scanDuration: Date.now() - Date.now() // Will be calculated properly in actual implementation
      };

    } finally {
      await page.close();
    }
  }
}

// CLI usage
async function main() {
  const url = process.argv[2];
  
  if (!url) {
    console.error('Usage: node scan.js <URL>');
    console.error('Example: node scan.js https://example.com');
    process.exit(1);
  }

  const scanner = new VibeSniffScanner();
  
  try {
    console.log(`🔍 Scanning: ${url}`);
    const result = await scanner.scan(url);
    
    // Generate visualization
    const report = scanner.visualizer.generateReport(result);
    
    console.log(JSON.stringify(result, null, 2));
    console.log(`📸 Screenshot saved as: out.png`);
    console.log(`📊 Interactive report: ${report.reportPath}`);
    console.log(`🌐 View report: file://${process.cwd()}/${report.reportPath}`);
  } catch (error) {
    console.error('❌ Scan failed:', error.message);
    process.exit(1);
  } finally {
    await scanner.cleanup();
  }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export default VibeSniffScanner;
