const mongoose = require('mongoose');

/**
 * Email Model
 * Stores email data fetched from Mailpit or other sources
 * 
 * Design Pattern: MVC (Model)
 * Purpose: Define email data structure and validation
 */
const emailSchema = new mongoose.Schema({
  // Email identification
  mailpitId: {
    type: String,
    unique: true,
    sparse: true, // Allows null values while maintaining uniqueness
    index: true
  },

  // Email headers
  subject: {
    type: String,
    required: [true, 'Email subject is required'],
    trim: true,
    maxlength: [500, 'Subject cannot exceed 500 characters']
  },

  from: {
    address: {
      type: String,
      required: [true, 'Sender address is required'],
      lowercase: true,
      trim: true
    },
    name: {
      type: String,
      trim: true
    }
  },

  to: [{
    address: {
      type: String,
      required: true,
      lowercase: true,
      trim: true
    },
    name: {
      type: String,
      trim: true
    }
  }],

  // Email content
  body: {
    text: {
      type: String,
      required: [true, 'Email body is required']
    },
    html: {
      type: String
    }
  },

  // Email metadata
  receivedAt: {
    type: Date,
    default: Date.now,
    index: true
  },

  language: {
    type: String,
    enum: ['en', 'de', 'fr', 'unknown'],
    default: 'unknown'
  },

  // Analysis status
  analyzed: {
    type: Boolean,
    default: false,
    index: true
  },

  analysisId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Analysis'
  },

  // Authentication results
  authentication: {
    dmarc: {
      status: {
        type: String,
        enum: ['pass', 'fail', 'unknown'],
        default: 'unknown'
      },
      details: String
    },
    spf: {
      status: {
        type: String,
        enum: ['pass', 'fail', 'unknown'],
        default: 'unknown'
      },
      details: String
    },
    dkim: {
      status: {
        type: String,
        enum: ['pass', 'fail', 'unknown'],
        default: 'unknown'
      },
      details: String
    }
  },

  // Raw email data (optional)
  raw: {
    type: String
  },

  // Attachments info
  attachments: [{
    filename: String,
    contentType: String,
    size: Number
  }]
}, {
  timestamps: true, // Adds createdAt and updatedAt
  collection: 'emails'
});

// Indexes for performance
emailSchema.index({ 'from.address': 1 });
emailSchema.index({ receivedAt: -1 });
emailSchema.index({ analyzed: 1, receivedAt: -1 });

// Virtual for full sender info
emailSchema.virtual('fromFull').get(function() {
  return this.from.name ? `${this.from.name} <${this.from.address}>` : this.from.address;
});

// Instance method: Mark as analyzed
emailSchema.methods.markAsAnalyzed = function(analysisId) {
  this.analyzed = true;
  this.analysisId = analysisId;
  return this.save();
};

// Static method: Find unanalyzed emails
emailSchema.statics.findUnanalyzed = function(limit = 10) {
  return this.find({ analyzed: false })
    .sort({ receivedAt: -1 })
    .limit(limit);
};

// Static method: Find by language
emailSchema.statics.findByLanguage = function(language) {
  return this.find({ language })
    .sort({ receivedAt: -1 });
};

// Pre-save middleware: Detect language from content
emailSchema.pre('save', function(next) {
  if (this.isNew && this.language === 'unknown') {
    const text = this.body.text.toLowerCase();
    
    // Simple language detection
    if (text.includes('der ') || text.includes('die ') || text.includes('das ')) {
      this.language = 'de';
    } else if (text.includes('le ') || text.includes('la ') || text.includes('les ')) {
      this.language = 'fr';
    } else {
      this.language = 'en';
    }
  }
  next();
});

const Email = mongoose.model('Email', emailSchema);

module.exports = Email;
