// services/passwordChangeService.js
const { v4: uuidv4 } = require('uuid');
const pool           = require('../db'); // Adjust the path to your database pool configuration

// Function to create a session
const createSession = async (userId) => {
    const sessionId = uuidv4();
    const expiration = new Date(Date.now() + 15 * 60 * 1000); // 15-minute expiration

    await pool.query(
        `
        INSERT INTO password_change_sessions (session_id, user_id, is_authenticated, is_new_password_verified, expiration)
        VALUES ($1, $2, $3, $4, $5)
        `,
        [sessionId, userId, true, false, expiration]
    );

    return sessionId;
};

module.exports = { createSession };
