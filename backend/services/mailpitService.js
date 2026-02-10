const axios = require('axios');

/**
 * Mailpit Service
 * Handles communication with Mailpit API to fetch emails
 * 
 * Purpose: Abstract Mailpit API interactions
 */
class MailpitService {
  constructor() {
    this.baseURL = process.env.MAILPIT_API_URL || 'http://127.0.0.1:8025/api/v1';
    this.client = axios.create({
      baseURL: this.baseURL,
      timeout: 10000,
      headers: {
        'Content-Type': 'application/json'
      }
    });
  }

  /**
   * Fetch all messages from Mailpit
   * @param {number} limit - Maximum number of messages to fetch
   * @returns {Promise<Array>} Array of email messages
   */
  async fetchMessages(limit = 50) {
    try {
      const response = await this.client.get('/messages', {
        params: { limit }
      });

      if (!response.data || !response.data.messages) {
        return [];
      }

      return response.data.messages;
    } catch (error) {
      console.error('[Mailpit] Error fetching messages:', error.message);
      throw new Error(`Failed to fetch messages from Mailpit: ${error.message}`);
    }
  }

  /**
   * Fetch a specific message by ID
   * @param {string} messageId - Mailpit message ID
   * @returns {Promise<Object>} Email message details
   */
  async fetchMessageById(messageId) {
    try {
      const response = await this.client.get(`/message/${messageId}`);
      return response.data;
    } catch (error) {
      console.error(`[Mailpit] Error fetching message ${messageId}:`, error.message);
      throw new Error(`Failed to fetch message: ${error.message}`);
    }
  }

  /**
   * Get message source (raw email)
   * @param {string} messageId - Mailpit message ID
   * @returns {Promise<string>} Raw email source
   */
  async getMessageSource(messageId) {
    try {
      const response = await this.client.get(`/message/${messageId}/raw`);
      return response.data;
    } catch (error) {
      console.error(`[Mailpit] Error fetching message source ${messageId}:`, error.message);
      throw new Error(`Failed to fetch message source: ${error.message}`);
    }
  }

  /**
   * Delete a message from Mailpit
   * @param {string} messageId - Mailpit message ID
   * @returns {Promise<boolean>} Success status
   */
  async deleteMessage(messageId) {
    try {
      await this.client.delete(`/message/${messageId}`);
      return true;
    } catch (error) {
      console.error(`[Mailpit] Error deleting message ${messageId}:`, error.message);
      return false;
    }
  }

  /**
   * Check Mailpit connection health
   * @returns {Promise<boolean>} Connection status
   */
  async checkHealth() {
    try {
      const response = await this.client.get('/messages', {
        params: { limit: 1 }
      });
      return response.status === 200;
    } catch (error) {
      console.error('[Mailpit] Health check failed:', error.message);
      return false;
    }
  }

  /**
   * Parse Mailpit message to Email model format
   * @param {Object} mailpitMessage - Raw Mailpit message
   * @returns {Object} Parsed email data
   */
  parseMessage(mailpitMessage) {
    return {
      mailpitId: mailpitMessage.ID,
      subject: mailpitMessage.Subject || '(No Subject)',
      from: {
        address: mailpitMessage.From?.Address || 'unknown@unknown.com',
        name: mailpitMessage.From?.Name || ''
      },
      to: mailpitMessage.To?.map(recipient => ({
        address: recipient.Address,
        name: recipient.Name || ''
      })) || [],
      body: {
        text: mailpitMessage.Text || '',
        html: mailpitMessage.HTML || ''
      },
      receivedAt: new Date(mailpitMessage.Created),
      attachments: mailpitMessage.Attachments?.map(att => ({
        filename: att.FileName,
        contentType: att.ContentType,
        size: att.Size
      })) || []
    };
  }

  /**
   * Extract authentication headers from message
   * @param {Object} mailpitMessage - Raw Mailpit message with headers
   * @returns {Object} Authentication results
   */
  extractAuthentication(mailpitMessage) {
    const headers = mailpitMessage.Headers || {};
    
    return {
      dmarc: this.parseDMARC(headers['Authentication-Results']),
      spf: this.parseSPF(headers['Received-SPF']),
      dkim: this.parseDKIM(headers['DKIM-Signature'])
    };
  }

  /**
   * Parse DMARC header
   * @private
   */
  parseDMARC(authResults) {
    if (!authResults) {
      return { status: 'unknown', details: 'No DMARC header found' };
    }

    const dmarc = authResults.toLowerCase();
    if (dmarc.includes('dmarc=pass')) {
      return { status: 'pass', details: 'DMARC authentication passed' };
    } else if (dmarc.includes('dmarc=fail')) {
      return { status: 'fail', details: 'DMARC authentication failed' };
    }

    return { status: 'unknown', details: 'DMARC status unclear' };
  }

  /**
   * Parse SPF header
   * @private
   */
  parseSPF(spfHeader) {
    if (!spfHeader) {
      return { status: 'unknown', details: 'No SPF header found' };
    }

    const spf = spfHeader.toLowerCase();
    if (spf.includes('pass')) {
      return { status: 'pass', details: 'SPF authentication passed' };
    } else if (spf.includes('fail')) {
      return { status: 'fail', details: 'SPF authentication failed' };
    }

    return { status: 'unknown', details: 'SPF status unclear' };
  }

  /**
   * Parse DKIM header
   * @private
   */
  parseDKIM(dkimHeader) {
    if (!dkimHeader) {
      return { status: 'unknown', details: 'No DKIM signature found' };
    }

    // DKIM presence usually indicates pass (simplified)
    return { status: 'pass', details: 'DKIM signature present' };
  }
}

// Export singleton instance
module.exports = new MailpitService();
