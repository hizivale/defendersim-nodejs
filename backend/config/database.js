const mongoose = require('mongoose');

/**
 * DatabaseConnection - Singleton Pattern
 * Ensures only one database connection instance exists throughout the application
 * 
 * Design Pattern: Singleton
 * Purpose: Manage MongoDB connection lifecycle and prevent multiple connections
 */
class DatabaseConnection {
  constructor() {
    if (DatabaseConnection.instance) {
      return DatabaseConnection.instance;
    }

    this.connection = null;
    this.isConnected = false;
    DatabaseConnection.instance = this;
  }

  /**
   * Connect to MongoDB database
   * @returns {Promise<mongoose.Connection>} MongoDB connection instance
   */
  async connect() {
    if (this.isConnected) {
      console.log('[Database] Using existing connection');
      return this.connection;
    }

    try {
      const mongoURI = process.env.MONGODB_URI || 'mongodb://localhost:27017/defendersim';
      
      const options = {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 45000,
      };

      await mongoose.connect(mongoURI, options);
      
      this.connection = mongoose.connection;
      this.isConnected = true;

      console.log(`[Database] Connected to MongoDB: ${this.connection.host}`);
      
      // Handle connection events
      this.connection.on('error', (err) => {
        console.error('[Database] Connection error:', err);
        this.isConnected = false;
      });

      this.connection.on('disconnected', () => {
        console.log('[Database] Disconnected from MongoDB');
        this.isConnected = false;
      });

      this.connection.on('reconnected', () => {
        console.log('[Database] Reconnected to MongoDB');
        this.isConnected = true;
      });

      return this.connection;
    } catch (error) {
      console.error('[Database] Connection failed:', error.message);
      throw error;
    }
  }

  /**
   * Disconnect from MongoDB database
   * @returns {Promise<void>}
   */
  async disconnect() {
    if (!this.isConnected) {
      return;
    }

    try {
      await mongoose.connection.close();
      this.isConnected = false;
      console.log('[Database] Disconnected successfully');
    } catch (error) {
      console.error('[Database] Disconnect error:', error.message);
      throw error;
    }
  }

  /**
   * Get connection status
   * @returns {boolean} Connection status
   */
  getStatus() {
    return this.isConnected;
  }

  /**
   * Get connection instance
   * @returns {mongoose.Connection} MongoDB connection
   */
  getConnection() {
    return this.connection;
  }
}

// Export singleton instance
const dbConnection = new DatabaseConnection();
module.exports = dbConnection;
