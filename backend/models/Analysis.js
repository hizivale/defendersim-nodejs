const mongoose = require('mongoose');

/**
 * Analysis Model
 * Stores phishing detection analysis results from multiple frameworks
 * 
 * Design Pattern: MVC (Model)
 * Purpose: Define analysis result structure and relationships
 */
const analysisSchema = new mongoose.Schema({
  // Reference to analyzed email
  emailId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Email',
    required: true,
    index: true
  },

  // Overall risk assessment
  riskLevel: {
    type: String,
    enum: ['HIGH', 'MEDIUM', 'LOW'],
    required: true,
    index: true
  },

  confidence: {
    type: Number,
    required: true,
    min: 0,
    max: 1,
    default: 0
  },

  // Classification (for metrics calculation)
  classification: {
    type: String,
    enum: ['TP', 'TN', 'FP', 'FN'], // True Positive, True Negative, False Positive, False Negative
    required: true
  },

  isPhishing: {
    type: Boolean,
    required: true
  },

  // Framework scores (0-100)
  frameworks: {
    mlClassifier: {
      score: {
        type: Number,
        min: 0,
        max: 100,
        required: true
      },
      patterns: [String],
      evidence: [String]
    },
    owasp: {
      score: {
        type: Number,
        min: 0,
        max: 100,
        required: true
      },
      patterns: [String],
      evidence: [String]
    },
    nist: {
      score: {
        type: Number,
        min: 0,
        max: 100,
        required: true
      },
      patterns: [String],
      evidence: [String]
    },
    iso27001: {
      score: {
        type: Number,
        min: 0,
        max: 100,
        required: true
      },
      patterns: [String],
      evidence: [String]
    },
    nessus: {
      score: {
        type: Number,
        min: 0,
        max: 100,
        required: true
      },
      patterns: [String],
      evidence: [String]
    },
    openvas: {
      score: {
        type: Number,
        min: 0,
        max: 100,
        required: true
      },
      patterns: [String],
      evidence: [String]
    }
  },

  // Ollama LLM analysis
  ollamaAnalysis: {
    summary: {
      type: String,
      required: true
    },
    reasoning: {
      type: String
    },
    recommendations: [String],
    processingTime: {
      type: Number // milliseconds
    }
  },

  // Detected indicators
  indicators: [{
    type: {
      type: String,
      enum: ['urgency', 'authority', 'suspicious_link', 'grammar_error', 'spoofing', 'credential_request', 'other']
    },
    description: String,
    severity: {
      type: String,
      enum: ['high', 'medium', 'low']
    }
  }],

  // Analysis metadata
  analyzedAt: {
    type: Date,
    default: Date.now,
    index: true
  },

  processingTime: {
    type: Number, // Total processing time in milliseconds
    required: true
  },

  version: {
    type: String,
    default: '1.0.0' // System version for tracking changes
  }
}, {
  timestamps: true,
  collection: 'analyses'
});

// Indexes for performance
analysisSchema.index({ riskLevel: 1, analyzedAt: -1 });
analysisSchema.index({ classification: 1 });
analysisSchema.index({ isPhishing: 1 });

// Virtual: Average framework score
analysisSchema.virtual('averageScore').get(function() {
  const scores = [
    this.frameworks.mlClassifier.score,
    this.frameworks.owasp.score,
    this.frameworks.nist.score,
    this.frameworks.iso27001.score,
    this.frameworks.nessus.score,
    this.frameworks.openvas.score
  ];
  return scores.reduce((a, b) => a + b, 0) / scores.length;
});

// Instance method: Get high-risk indicators
analysisSchema.methods.getHighRiskIndicators = function() {
  return this.indicators.filter(ind => ind.severity === 'high');
};

// Static method: Get statistics
analysisSchema.statics.getStatistics = async function() {
  const total = await this.countDocuments();
  const highRisk = await this.countDocuments({ riskLevel: 'HIGH' });
  const mediumRisk = await this.countDocuments({ riskLevel: 'MEDIUM' });
  const lowRisk = await this.countDocuments({ riskLevel: 'LOW' });

  const tp = await this.countDocuments({ classification: 'TP' });
  const tn = await this.countDocuments({ classification: 'TN' });
  const fp = await this.countDocuments({ classification: 'FP' });
  const fn = await this.countDocuments({ classification: 'FN' });

  // Calculate metrics
  const accuracy = total > 0 ? ((tp + tn) / total) * 100 : 0;
  const precision = (tp + fp) > 0 ? (tp / (tp + fp)) * 100 : 0;
  const recall = (tp + fn) > 0 ? (tp / (tp + fn)) * 100 : 0;
  const f1Score = (precision + recall) > 0 ? (2 * (precision * recall) / (precision + recall)) : 0;

  return {
    total,
    riskDistribution: {
      high: highRisk,
      medium: mediumRisk,
      low: lowRisk
    },
    classification: { tp, tn, fp, fn },
    metrics: {
      accuracy: accuracy.toFixed(1),
      precision: precision.toFixed(1),
      recall: recall.toFixed(1),
      f1Score: f1Score.toFixed(1)
    }
  };
};

// Static method: Get recent analyses
analysisSchema.statics.getRecent = function(limit = 10) {
  return this.find()
    .populate('emailId', 'subject from receivedAt')
    .sort({ analyzedAt: -1 })
    .limit(limit);
};

// Static method: Get framework comparison data
analysisSchema.statics.getFrameworkComparison = async function() {
  const analyses = await this.find();
  
  const frameworkScores = {
    mlClassifier: 0,
    owasp: 0,
    nist: 0,
    iso27001: 0,
    nessus: 0,
    openvas: 0
  };

  analyses.forEach(analysis => {
    frameworkScores.mlClassifier += analysis.frameworks.mlClassifier.score;
    frameworkScores.owasp += analysis.frameworks.owasp.score;
    frameworkScores.nist += analysis.frameworks.nist.score;
    frameworkScores.iso27001 += analysis.frameworks.iso27001.score;
    frameworkScores.nessus += analysis.frameworks.nessus.score;
    frameworkScores.openvas += analysis.frameworks.openvas.score;
  });

  const count = analyses.length || 1;
  
  return {
    mlClassifier: (frameworkScores.mlClassifier / count).toFixed(1),
    owasp: (frameworkScores.owasp / count).toFixed(1),
    nist: (frameworkScores.nist / count).toFixed(1),
    iso27001: (frameworkScores.iso27001 / count).toFixed(1),
    nessus: (frameworkScores.nessus / count).toFixed(1),
    openvas: (frameworkScores.openvas / count).toFixed(1)
  };
};

const Analysis = mongoose.model('Analysis', analysisSchema);

module.exports = Analysis;
