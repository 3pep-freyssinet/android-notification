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

//const REFRESH_EXPIRY = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days in the future
//const JWT_EXPIRY     = '1d'; 

const JWT_EXPIRY 		= process.env.JWT_EXPIRY;
const REFRESH_EXPIRY 		= process.env.JWT_REFRESH_EXPIRY;

const MAX_ATTEMPTS = 3;
const LOCKOUT_DURATION = 60 * 60 * 1000; // 1 hour in milliseconds

const CAPTCHA_SECRET   = process.env.CAPTCHA_SECRET;
const CAPTCHA_SITE_KEY = process.env.CAPTCHA_SITE_KEY;

//console.log('process.env.DATABASE_URL = ' + process.env.DATABASE_URL);

console.log('pool = ' + pool);

console.log('fcm_tokens_controler');

//store FCM tokens
exports.storeFCMToken = async (req, res) => {

   console.log('fcm tokens : store fcm token ***********************************************************************');
	
   // Extract token and user information
   const { fcm_token } = req.body;

   // Validate input
   if (!fcm_token) {
	return res.status(400).json({ error: 'FCM token is required' });
   }	

const userId = req.user.userId; // Assuming user ID comes from middleware after verifying the JWT
	
console.log('storeFCMTokens : user_id = ', userId, ' fcm_token = ', fcm_token, '\n');
	
  try {
    /*
    const result = await pool.query('INSERT into fcm_tokens (user_id, fcm_token) VALUES ($1, $2) RETURNING id', [
				userId,
				fcm_token	
			]);
    */
	const query = `
		INSERT INTO fcm_tokens (user_id, device_token, last_updated)
		VALUES ($1, $2, CURRENT_TIMESTAMP) RETURNING id
		ON CONFLICT (user_id)
		DO UPDATE SET device_token = EXCLUDED.device_token, last_updated = CURRENT_TIMESTAMP;
	  `;
	
	  const result = await pool.query('INSERT into fcm_tokens (user_id, fcm_token) VALUES ($1, $2) RETURNING id', [
				userId,
				fcm_token	
			]);  
	  
    //console.log('storeFCMTokens / : result : ', JSON.stringify(result));

    if(result.rowCount == 1){
	console.log('storeFCMTokens successfull : id : ', result.rows[0].id);
    	res.status(200).json({ 
			message: 'fcm registered successfully', 
			id:result.rows[0].id
		        });
    }else{
	console.log('storeFCMTokens failed');
    	res.status(500).send('Internal server error : Error storing FCM tokens');
    }
  } catch (err) {
      console.error('Error storing FCM tokens :', err);
      res.status(500).send('Internal server error : Error storing FCM tokens');
  }
}

// get all fcm tokens
exports.getAllFCMTokens = async (req, res) => {
	   
console.log('getAllFCMTokens\n');
	
  try {
    const result = await pool.query('SELECT id, user_id, fcm_token FROM fcm_tokens');
    const tokens = result.rows;
	
    console.log('getAllFCMTokens / : tokens : ', JSON.stringify(tokens));
    
    //res.status(200).json({tokens});
	  
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
    const result = await pool.query('SELECT id, user_id, fcm_token FROM fcm_tokens');
    const tokens = result.rows;
	
    //console.log('getAllFCMTokens / : tokens : ', JSON.stringify(tokens));
	
    res.render('index', { tokens });
  } catch (err) {
      console.error('Error retrieving FCM tokens:', err);
      res.status(500).send('Internal server error');
  }
}
