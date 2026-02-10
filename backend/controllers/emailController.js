const Email = require('../models/Email');
const mailpitService = require('../services/mailpitService');

/**
 * Email Controller
 * Handles email-related operations
 * 
 * Design Pattern: MVC (Controller)
 * Purpose: Business logic for email management
 */

/**
 * Fetch emails from Mailpit and store in database
 * @route GET /api/emails/sync
 */
exports.syncEmails = async (req, res, next) => {
  try {
    const limit = parseInt(req.query.limit) || 50;

    console.log(`[EmailController] Syncing emails from Mailpit (limit: ${limit})`);

    // Fetch messages from Mailpit
    const mailpitMessages = await mailpitService.fetchMessages(limit);

    if (mailpitMessages.length === 0) {
      return res.status(200).json({
        success: true,
        message: 'No new emails found in Mailpit',
        count: 0,
        emails: []
      });
    }

    const syncedEmails = [];
    const skippedEmails = [];

    // Process each message
    for (const mailpitMsg of mailpitMessages) {
      try {
        // Check if email already exists
        const existingEmail = await Email.findOne({ mailpitId: mailpitMsg.ID });
        
        if (existingEmail) {
          skippedEmails.push(mailpitMsg.ID);
          continue;
        }

        // Parse message
        const emailData = mailpitService.parseMessage(mailpitMsg);

        // Fetch full message for authentication headers
        const fullMessage = await mailpitService.fetchMessageById(mailpitMsg.ID);
        emailData.authentication = mailpitService.extractAuthentication(fullMessage);

        // Create email in database
        const email = await Email.create(emailData);
        syncedEmails.push(email);

        console.log(`[EmailController] Synced email: ${email.subject}`);
      } catch (error) {
        console.error(`[EmailController] Error syncing email ${mailpitMsg.ID}:`, error.message);
      }
    }

    res.status(200).json({
      success: true,
      message: `Synced ${syncedEmails.length} emails`,
      count: syncedEmails.length,
      skipped: skippedEmails.length,
      emails: syncedEmails
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get all emails from database
 * @route GET /api/emails
 */
exports.getEmails = async (req, res, next) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const filter = {};
    
    // Filter by analysis status
    if (req.query.analyzed !== undefined) {
      filter.analyzed = req.query.analyzed === 'true';
    }

    // Filter by language
    if (req.query.language) {
      filter.language = req.query.language;
    }

    const total = await Email.countDocuments(filter);
    const emails = await Email.find(filter)
      .sort({ receivedAt: -1 })
      .skip(skip)
      .limit(limit)
      .populate('analysisId');

    res.status(200).json({
      success: true,
      count: emails.length,
      total,
      page,
      pages: Math.ceil(total / limit),
      emails
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get single email by ID
 * @route GET /api/emails/:id
 */
exports.getEmailById = async (req, res, next) => {
  try {
    const email = await Email.findById(req.params.id).populate('analysisId');

    if (!email) {
      return res.status(404).json({
        success: false,
        message: 'Email not found'
      });
    }

    res.status(200).json({
      success: true,
      email
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get unanalyzed emails
 * @route GET /api/emails/unanalyzed
 */
exports.getUnanalyzedEmails = async (req, res, next) => {
  try {
    const limit = parseInt(req.query.limit) || 10;
    const emails = await Email.findUnanalyzed(limit);

    res.status(200).json({
      success: true,
      count: emails.length,
      emails
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Delete email by ID
 * @route DELETE /api/emails/:id
 */
exports.deleteEmail = async (req, res, next) => {
  try {
    const email = await Email.findById(req.params.id);

    if (!email) {
      return res.status(404).json({
        success: false,
        message: 'Email not found'
      });
    }

    // Delete from Mailpit if mailpitId exists
    if (email.mailpitId) {
      await mailpitService.deleteMessage(email.mailpitId);
    }

    // Delete from database
    await email.deleteOne();

    res.status(200).json({
      success: true,
      message: 'Email deleted successfully'
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Get email statistics
 * @route GET /api/emails/stats
 */
exports.getEmailStats = async (req, res, next) => {
  try {
    const total = await Email.countDocuments();
    const analyzed = await Email.countDocuments({ analyzed: true });
    const unanalyzed = await Email.countDocuments({ analyzed: false });

    const languageStats = await Email.aggregate([
      {
        $group: {
          _id: '$language',
          count: { $sum: 1 }
        }
      }
    ]);

    const recentEmails = await Email.find()
      .sort({ receivedAt: -1 })
      .limit(5)
      .select('subject from receivedAt analyzed');

    res.status(200).json({
      success: true,
      stats: {
        total,
        analyzed,
        unanalyzed,
        languages: languageStats,
        recent: recentEmails
      }
    });
  } catch (error) {
    next(error);
  }
};
