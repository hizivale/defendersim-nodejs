const axios = require('axios');

/**
 * Ollama Service
 * Handles communication with Ollama LLM for AI-powered analysis
 * 
 * Purpose: Abstract Ollama API interactions and provide RAG-based analysis
 */
class OllamaService {
  constructor() {
    this.baseURL = process.env.OLLAMA_API_URL || 'http://localhost:11434';
    this.model = process.env.OLLAMA_MODEL || 'llama3.2:3b';
    this.client = axios.create({
      baseURL: this.baseURL,
      timeout: 60000, // 60 seconds for LLM responses
      headers: {
        'Content-Type': 'application/json'
      }
    });
  }

  /**
   * Analyze email using Ollama LLM with RAG
   * @param {Object} emailData - Email content and metadata
   * @param {Object} frameworkResults - Results from 6 detection frameworks
   * @returns {Promise<Object>} LLM analysis result
   */
  async analyzeEmail(emailData, frameworkResults) {
    const startTime = Date.now();

    try {
      const prompt = this.buildAnalysisPrompt(emailData, frameworkResults);
      
      const response = await this.client.post('/api/generate', {
        model: this.model,
        prompt: prompt,
        stream: false,
        options: {
          temperature: 0.3, // Lower temperature for more consistent results
          top_p: 0.9,
          top_k: 40
        }
      });

      const processingTime = Date.now() - startTime;

      return {
        summary: this.extractSummary(response.data.response),
        reasoning: this.extractReasoning(response.data.response),
        recommendations: this.extractRecommendations(response.data.response),
        rawResponse: response.data.response,
        processingTime
      };
    } catch (error) {
      console.error('[Ollama] Analysis error:', error.message);
      
      // Fallback response if Ollama fails
      return {
        summary: 'LLM analysis unavailable. Using framework-based assessment.',
        reasoning: 'Ollama service is not responding. Analysis based on detection frameworks only.',
        recommendations: ['Verify Ollama service is running', 'Check email manually'],
        processingTime: Date.now() - startTime
      };
    }
  }

  /**
   * Build analysis prompt with RAG context
   * @private
   */
  buildAnalysisPrompt(emailData, frameworkResults) {
    const avgScore = this.calculateAverageScore(frameworkResults);
    const riskLevel = this.determineRiskLevel(avgScore);

    return `You are a cybersecurity expert analyzing an email for phishing threats.

EMAIL DETAILS:
Subject: ${emailData.subject}
From: ${emailData.from.address}
Body: ${emailData.body.text.substring(0, 1000)}

DETECTION FRAMEWORK RESULTS:
- ML Classifier: ${frameworkResults.mlClassifier.score}% (Patterns: ${frameworkResults.mlClassifier.patterns.join(', ')})
- OWASP: ${frameworkResults.owasp.score}% (Patterns: ${frameworkResults.owasp.patterns.join(', ')})
- NIST CSF: ${frameworkResults.nist.score}% (Patterns: ${frameworkResults.nist.patterns.join(', ')})
- ISO/IEC 27001: ${frameworkResults.iso27001.score}% (Patterns: ${frameworkResults.iso27001.patterns.join(', ')})
- Nessus: ${frameworkResults.nessus.score}% (Patterns: ${frameworkResults.nessus.patterns.join(', ')})
- OpenVAS: ${frameworkResults.openvas.score}% (Patterns: ${frameworkResults.openvas.patterns.join(', ')})

Average Detection Score: ${avgScore}%
Preliminary Risk Level: ${riskLevel}

AUTHENTICATION:
- DMARC: ${emailData.authentication?.dmarc?.status || 'unknown'}
- SPF: ${emailData.authentication?.spf?.status || 'unknown'}
- DKIM: ${emailData.authentication?.dkim?.status || 'unknown'}

TASK:
Analyze this email and provide:
1. SUMMARY: A 2-3 sentence assessment of whether this is phishing
2. REASONING: Explain why based on the framework results and email content
3. RECOMMENDATIONS: List 3-5 specific actions (e.g., "Delete immediately", "Report to IT", "Verify sender")

Format your response as:
SUMMARY: [your summary]
REASONING: [your reasoning]
RECOMMENDATIONS: [numbered list]`;
  }

  /**
   * Calculate average framework score
   * @private
   */
  calculateAverageScore(frameworks) {
    const scores = [
      frameworks.mlClassifier.score,
      frameworks.owasp.score,
      frameworks.nist.score,
      frameworks.iso27001.score,
      frameworks.nessus.score,
      frameworks.openvas.score
    ];
    return (scores.reduce((a, b) => a + b, 0) / scores.length).toFixed(1);
  }

  /**
   * Determine risk level from average score
   * @private
   */
  determineRiskLevel(avgScore) {
    if (avgScore >= 70) return 'HIGH';
    if (avgScore >= 40) return 'MEDIUM';
    return 'LOW';
  }

  /**
   * Extract summary from LLM response
   * @private
   */
  extractSummary(response) {
    const match = response.match(/SUMMARY:\s*(.+?)(?=REASONING:|$)/s);
    return match ? match[1].trim() : 'Analysis completed. See full report for details.';
  }

  /**
   * Extract reasoning from LLM response
   * @private
   */
  extractReasoning(response) {
    const match = response.match(/REASONING:\s*(.+?)(?=RECOMMENDATIONS:|$)/s);
    return match ? match[1].trim() : 'Based on framework analysis results.';
  }

  /**
   * Extract recommendations from LLM response
   * @private
   */
  extractRecommendations(response) {
    const match = response.match(/RECOMMENDATIONS:\s*(.+?)$/s);
    if (!match) return ['Review email carefully', 'Verify sender identity', 'Do not click links'];

    const text = match[1].trim();
    const recommendations = text
      .split('\n')
      .filter(line => line.trim().length > 0)
      .map(line => line.replace(/^\d+\.\s*/, '').trim())
      .filter(line => line.length > 0);

    return recommendations.length > 0 ? recommendations : ['Review email carefully'];
  }

  /**
   * Check Ollama service health
   * @returns {Promise<boolean>} Service status
   */
  async checkHealth() {
    try {
      const response = await this.client.get('/api/tags');
      return response.status === 200;
    } catch (error) {
      console.error('[Ollama] Health check failed:', error.message);
      return false;
    }
  }

  /**
   * List available models
   * @returns {Promise<Array>} Available models
   */
  async listModels() {
    try {
      const response = await this.client.get('/api/tags');
      return response.data.models || [];
    } catch (error) {
      console.error('[Ollama] Error listing models:', error.message);
      return [];
    }
  }
}

// Export singleton instance
module.exports = new OllamaService();
