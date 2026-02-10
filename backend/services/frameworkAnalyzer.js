/**
 * Framework Analyzer Service
 * Implements 6 security frameworks for phishing detection
 * 
 * Design Pattern: Factory Pattern
 * Purpose: Create different analyzer instances based on framework type
 */

/**
 * Base Analyzer Class
 * All framework analyzers extend this class
 */
class BaseAnalyzer {
  constructor(name) {
    this.name = name;
  }

  /**
   * Analyze email (to be implemented by subclasses)
   * @param {Object} emailData - Email content and metadata
   * @returns {Object} Analysis result with score, patterns, and evidence
   */
  analyze(emailData) {
    throw new Error('analyze() must be implemented by subclass');
  }

  /**
   * Calculate score based on detected patterns
   * @protected
   */
  calculateScore(detectedPatterns, totalPatterns) {
    if (totalPatterns === 0) return 0;
    return Math.min(100, Math.round((detectedPatterns.length / totalPatterns) * 100));
  }
}

/**
 * ML Classifier Analyzer
 * Uses Naive Bayes-inspired pattern matching with TF-IDF concepts
 */
class MLClassifierAnalyzer extends BaseAnalyzer {
  constructor() {
    super('ML Classifier');
    this.phishingKeywords = [
      'urgent', 'verify', 'suspended', 'locked', 'confirm', 'click here',
      'account', 'security', 'update', 'immediately', 'expire', 'limited time'
    ];
  }

  analyze(emailData) {
    const text = `${emailData.subject} ${emailData.body.text}`.toLowerCase();
    const patterns = [];
    const evidence = [];

    // Keyword detection
    this.phishingKeywords.forEach(keyword => {
      if (text.includes(keyword)) {
        patterns.push(`Urgency keyword: "${keyword}"`);
        const context = this.extractContext(text, keyword);
        evidence.push(`Found "${keyword}" in context: "${context}"`);
      }
    });

    // URL analysis
    const urls = this.extractURLs(emailData.body.text);
    urls.forEach(url => {
      if (this.isSuspiciousURL(url)) {
        patterns.push('Suspicious URL detected');
        evidence.push(`Suspicious URL: ${url}`);
      }
    });

    // Grammar and spelling errors
    if (this.hasGrammarErrors(text)) {
      patterns.push('Grammar/spelling errors detected');
      evidence.push('Multiple grammar or spelling errors found');
    }

    const score = this.calculateScore(patterns, 10);

    return { score, patterns, evidence };
  }

  extractContext(text, keyword, contextLength = 50) {
    const index = text.indexOf(keyword);
    if (index === -1) return '';
    const start = Math.max(0, index - contextLength);
    const end = Math.min(text.length, index + keyword.length + contextLength);
    return text.substring(start, end).trim();
  }

  extractURLs(text) {
    const urlRegex = /(https?:\/\/[^\s]+)/g;
    return text.match(urlRegex) || [];
  }

  isSuspiciousURL(url) {
    const suspiciousPatterns = [
      /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, // IP address
      /[a-z0-9-]+\.(tk|ml|ga|cf|gq)/, // Suspicious TLDs
      /-verify|-secure|-login|-account/, // Phishing keywords in domain
      /@/ // @ symbol in URL
    ];
    return suspiciousPatterns.some(pattern => pattern.test(url));
  }

  hasGrammarErrors(text) {
    // Simple heuristic: multiple capitalization errors or excessive punctuation
    const capsErrors = (text.match(/[A-Z]{2,}/g) || []).length;
    const excessPunctuation = (text.match(/[!?]{2,}/g) || []).length;
    return capsErrors > 3 || excessPunctuation > 2;
  }
}

/**
 * OWASP Analyzer
 * Checks for web application security vulnerabilities
 */
class OWASPAnalyzer extends BaseAnalyzer {
  constructor() {
    super('OWASP');
  }

  analyze(emailData) {
    const patterns = [];
    const evidence = [];
    const text = emailData.body.text;

    // Check for injection attempts
    if (/<script|javascript:|onerror=/i.test(text)) {
      patterns.push('XSS attempt detected');
      evidence.push('Script tags or JavaScript protocol found in email');
    }

    // Check for SQL injection patterns
    if (/'|--|;|union|select|drop/i.test(text)) {
      patterns.push('SQL injection patterns detected');
      evidence.push('SQL keywords found in email content');
    }

    // Check for malicious redirects
    const urls = this.extractURLs(text);
    urls.forEach(url => {
      if (url.includes('redirect') || url.includes('%2F')) {
        patterns.push('Malicious redirect detected');
        evidence.push(`Suspicious redirect URL: ${url}`);
      }
    });

    // Check for form submissions
    if (/<form|<input/i.test(text)) {
      patterns.push('HTML form detected');
      evidence.push('Email contains HTML form elements');
    }

    const score = this.calculateScore(patterns, 8);
    return { score, patterns, evidence };
  }

  extractURLs(text) {
    const urlRegex = /(https?:\/\/[^\s]+)/g;
    return text.match(urlRegex) || [];
  }
}

/**
 * NIST CSF Analyzer
 * Validates authentication and sender reputation
 */
class NISTAnalyzer extends BaseAnalyzer {
  constructor() {
    super('NIST CSF');
  }

  analyze(emailData) {
    const patterns = [];
    const evidence = [];

    // Check authentication
    const auth = emailData.authentication || {};
    
    if (auth.dmarc?.status === 'fail') {
      patterns.push('DMARC authentication failed');
      evidence.push('DMARC: Sender domain authentication failed');
    }

    if (auth.spf?.status === 'fail') {
      patterns.push('SPF authentication failed');
      evidence.push('SPF: Sender IP not authorized');
    }

    if (auth.dkim?.status === 'fail') {
      patterns.push('DKIM authentication failed');
      evidence.push('DKIM: Email signature verification failed');
    }

    // Check sender domain
    const senderDomain = emailData.from.address.split('@')[1];
    if (this.isSuspiciousDomain(senderDomain)) {
      patterns.push('Suspicious sender domain');
      evidence.push(`Domain "${senderDomain}" appears suspicious`);
    }

    // Check for domain spoofing
    if (this.isDomainSpoofing(emailData.from.address, emailData.subject)) {
      patterns.push('Possible domain spoofing');
      evidence.push('Sender domain does not match claimed organization');
    }

    const score = this.calculateScore(patterns, 7);
    return { score, patterns, evidence };
  }

  isSuspiciousDomain(domain) {
    const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq'];
    return suspiciousTLDs.some(tld => domain.endsWith(tld));
  }

  isDomainSpoofing(email, subject) {
    const knownBrands = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'bank'];
    const domain = email.split('@')[1].toLowerCase();
    const subjectLower = subject.toLowerCase();

    return knownBrands.some(brand => 
      subjectLower.includes(brand) && !domain.includes(brand)
    );
  }
}

/**
 * ISO/IEC 27001 Analyzer
 * Checks information security management compliance
 */
class ISO27001Analyzer extends BaseAnalyzer {
  constructor() {
    super('ISO/IEC 27001');
  }

  analyze(emailData) {
    const patterns = [];
    const evidence = [];
    const text = `${emailData.subject} ${emailData.body.text}`.toLowerCase();

    // Check for sensitive data requests
    const sensitiveTerms = ['password', 'credit card', 'ssn', 'social security', 'pin', 'account number'];
    sensitiveTerms.forEach(term => {
      if (text.includes(term)) {
        patterns.push('Sensitive data request detected');
        evidence.push(`Request for sensitive information: "${term}"`);
      }
    });

    // Check for unencrypted data transmission
    const urls = this.extractURLs(emailData.body.text);
    urls.forEach(url => {
      if (url.startsWith('http://') && !url.startsWith('https://')) {
        patterns.push('Unencrypted link detected');
        evidence.push(`Insecure HTTP link: ${url}`);
      }
    });

    // Check for policy violations
    if (text.includes('bypass') || text.includes('skip verification')) {
      patterns.push('Security policy violation');
      evidence.push('Email suggests bypassing security procedures');
    }

    const score = this.calculateScore(patterns, 6);
    return { score, patterns, evidence };
  }

  extractURLs(text) {
    const urlRegex = /(https?:\/\/[^\s]+)/g;
    return text.match(urlRegex) || [];
  }
}

/**
 * Nessus Analyzer
 * Scans for known exploits and malware signatures
 */
class NessusAnalyzer extends BaseAnalyzer {
  constructor() {
    super('Nessus');
  }

  analyze(emailData) {
    const patterns = [];
    const evidence = [];

    // Check attachments
    if (emailData.attachments && emailData.attachments.length > 0) {
      emailData.attachments.forEach(att => {
        if (this.isSuspiciousAttachment(att.filename)) {
          patterns.push('Suspicious attachment detected');
          evidence.push(`Suspicious file: ${att.filename}`);
        }
      });
    }

    // Check for exploit kits
    const text = emailData.body.text;
    if (/exploit|payload|shellcode|metasploit/i.test(text)) {
      patterns.push('Exploit kit indicators');
      evidence.push('Exploit-related keywords found');
    }

    // Check for known malware signatures
    if (this.hasmalwareSignature(text)) {
      patterns.push('Malware signature detected');
      evidence.push('Known malware patterns found in email');
    }

    const score = this.calculateScore(patterns, 5);
    return { score, patterns, evidence };
  }

  isSuspiciousAttachment(filename) {
    const suspiciousExtensions = ['.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.jar', '.zip'];
    return suspiciousExtensions.some(ext => filename.toLowerCase().endsWith(ext));
  }

  hasmalwareSignature(text) {
    const malwareKeywords = ['ransomware', 'trojan', 'virus', 'malware', 'backdoor'];
    return malwareKeywords.some(keyword => text.toLowerCase().includes(keyword));
  }
}

/**
 * OpenVAS Analyzer
 * Open-source vulnerability assessment
 */
class OpenVASAnalyzer extends BaseAnalyzer {
  constructor() {
    super('OpenVAS');
  }

  analyze(emailData) {
    const patterns = [];
    const evidence = [];
    const text = `${emailData.subject} ${emailData.body.text}`.toLowerCase();

    // Check for zero-day indicators
    if (text.includes('new') && text.includes('update') && text.includes('urgent')) {
      patterns.push('Zero-day threat indicators');
      evidence.push('Combination of urgency and update request detected');
    }

    // Check for suspicious file types
    const fileExtensions = text.match(/\.[a-z]{2,4}\b/g) || [];
    fileExtensions.forEach(ext => {
      if (['.exe', '.scr', '.bat', '.vbs'].includes(ext)) {
        patterns.push('Suspicious file type mentioned');
        evidence.push(`Executable file type mentioned: ${ext}`);
      }
    });

    // Check for exploit attempts
    const urls = this.extractURLs(emailData.body.text);
    urls.forEach(url => {
      if (url.length > 200 || url.includes('%00') || url.includes('../')) {
        patterns.push('Exploit attempt in URL');
        evidence.push(`Suspicious URL structure: ${url.substring(0, 50)}...`);
      }
    });

    const score = this.calculateScore(patterns, 5);
    return { score, patterns, evidence };
  }

  extractURLs(text) {
    const urlRegex = /(https?:\/\/[^\s]+)/g;
    return text.match(urlRegex) || [];
  }
}

/**
 * Framework Analyzer Factory
 * Creates analyzer instances based on framework type
 * 
 * Design Pattern: Factory Pattern
 */
class FrameworkAnalyzerFactory {
  /**
   * Create analyzer instance
   * @param {string} type - Framework type
   * @returns {BaseAnalyzer} Analyzer instance
   */
  static createAnalyzer(type) {
    switch (type.toLowerCase()) {
      case 'ml':
      case 'mlclassifier':
        return new MLClassifierAnalyzer();
      case 'owasp':
        return new OWASPAnalyzer();
      case 'nist':
        return new NISTAnalyzer();
      case 'iso27001':
        return new ISO27001Analyzer();
      case 'nessus':
        return new NessusAnalyzer();
      case 'openvas':
        return new OpenVASAnalyzer();
      default:
        throw new Error(`Unknown framework type: ${type}`);
    }
  }

  /**
   * Analyze email with all frameworks
   * @param {Object} emailData - Email content and metadata
   * @returns {Object} Combined analysis results from all frameworks
   */
  static analyzeWithAllFrameworks(emailData) {
    const frameworks = ['ml', 'owasp', 'nist', 'iso27001', 'nessus', 'openvas'];
    const results = {};

    frameworks.forEach(framework => {
      const analyzer = this.createAnalyzer(framework);
      results[framework === 'ml' ? 'mlClassifier' : framework] = analyzer.analyze(emailData);
    });

    return results;
  }
}

module.exports = {
  FrameworkAnalyzerFactory,
  BaseAnalyzer,
  MLClassifierAnalyzer,
  OWASPAnalyzer,
  NISTAnalyzer,
  ISO27001Analyzer,
  NessusAnalyzer,
  OpenVASAnalyzer
};
