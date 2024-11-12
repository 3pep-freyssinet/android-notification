/*
400 Bad Request: Used when the server cannot process the request due to client-side errors like invalid parameters, malformed data, or missing fields.
	Example: "Wrong username or password"
401 Unauthorized: Used when the user is not authenticated, meaning they failed to provide valid credentials.
	Example: "Unauthorized access"
403 Forbidden: Used when the user is authenticated but doesn't have permission to access the requested resource.
	Example: "You do not have permission to access this resource"
404 Not Found: Used when the requested resource cannot be found.
	Example: "User not found"	
500 Internal Server Error: Used when there is a server-side error (e.g., a bug or unhandled exception).
	Example: "Something went wrong on the server"
*/

require('dotenv').config();
const pool   = require('../db'); // Assuming you use a database pool for Postgres or MySQL
const bcrypt = require('bcryptjs');
const jwt    = require('jsonwebtoken');
const crypto = require('crypto');
const axios  = require('axios');
const http   = require('http');

const JWT_SECRET 		= process.env.JWT_SECRET;
const REFRESH_TOKEN_SECRET 	= process.env.REFRESH_TOKEN_SECRET;

const REFRESH_EXPIRY = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days in the future
const JWT_EXPIRY     = '1d'; 

const MAX_ATTEMPTS = 3;
const LOCKOUT_DURATION = 60 * 60 * 1000; // 1 hour in milliseconds

const CAPTCHA_SECRET   = process.env.CAPTCHA_SECRET;
const CAPTCHA_SITE_KEY = process.env.CAPTCHA_SITE_KEY;

//console.log('process.env.DATABASE_URL = ' + process.env.DATABASE_URL);

console.log('pool = ' + pool);

// get all fcm tokens
exports.getAllFCMTokens = async (req, res) => {
	   
console.log('getAllFCMTokens\n');
	
  try {
    const result = await pool.query('SELECT id, user_id, device_token FROM fcm_tokens');
    const tokens = result.rows;
	
	   //console.log('getAllFCMTokens / : tokens : ', JSON.stringify(tokens));
	
    res.render('index', { tokens });
  } catch (err) {
      console.error('Error retrieving FCM tokens:', err);
      res.status(500).send('Internal server error');
  }
}

// post all fcm tokens
exports.postAllFCMTokens = async (req, res) => {
	   
console.log('postAllFCMTokens\n');
	
  try {
    const result = await pool.query('SELECT id, user_id, device_token FROM fcm_tokens');
    const tokens = result.rows;
	
	   //console.log('getAllFCMTokens / : tokens : ', JSON.stringify(tokens));
	
    res.render('index', { tokens });
  } catch (err) {
      console.error('Error retrieving FCM tokens:', err);
      res.status(500).send('Internal server error');
  }
}
