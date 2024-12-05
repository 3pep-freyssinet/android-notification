
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

	    
	

};
