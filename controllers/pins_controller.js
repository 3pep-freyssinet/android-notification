
require('dotenv').config();
const pool   = require('../db'); // Assuming you use a database pool for Postgres or MySQL
const bcrypt = require('bcryptjs');
const jwt    = require('jsonwebtoken');
const crypto = require('crypto');

const JWT_SECRET 			= process.env.JWT_SECRET;
const REFRESH_TOKEN_SECRET 	= process.env.REFRESH_TOKEN_SECRET;

const REFRESH_EXPIRY = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days in the future
const JWT_EXPIRY     = '1d'; 
const ALERT_TIME     = 3 * 24 * 60 * 60 * 1000 //3 days, trigger

//console.log('process.env.DATABASE_URL = ' + process.env.DATABASE_URL);
console.log('pool = ' + pool);

// Get SHA256 pins
exports.getPins = async (req, res) => {
    // get pins endpoint
    
    console.log('get pins \n');
	
	const pins = req.body.pins;
	
	console.log("get pins : pins : ", pins );
	
    // Verify the refresh token
	const {userId, expires_at} = await verifyRefreshToken(refreshToken);
	
	console.log("refresh-jwt-token : refreshToken : userId = ",userId, " expires_at = ", expires_at);
	
	// Create a Date object from the string
    const date = new Date(expires_at);

    // Subtract 3 days (3 days * 24 hours * 60 minutes * 60 seconds * 1000 milliseconds)
    date.setTime(date.getTime() - ALERT_TIME);

    // Print the new date
    const triggerTime = date.toISOString();
	
	var isRefreshTokenExpired = Date.now() > triggerTime;
	
	console.log("refresh-jwt-token : is refreshToken expired  : ", isRefreshTokenExpired );
	
	var newRefreshToken;
	if(isRefreshTokenExpired){//the 'refresh-token' is not expired but it remains less than 3 days to dead date.
		//Generate new 'refresh-token'
		newRefreshToken = generateRefreshToken();
		
		//update the db
		await updateRefreshToken(userId, newRefreshToken);
	}
	
	console.log("refresh-jwt-token : newRefreshToken : ",newRefreshToken);
	
	// Generate a new jwt token (JWT)
    newJWTToken = jwt.sign({ userId: userId }, JWT_SECRET, { expiresIn: JWT_EXPIRY });
    res.json({ new_jwt_token: newJWTToken, new_refresh_token: newRefreshToken, new_refresh_token_expiry: REFRESH_EXPIRY});
			
	//update the jwt_tokens table
	if(newJWTToken != null){
		const result = await updateJWTToken(userId, newJWTToken);
	}
};
