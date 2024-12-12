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

//const REFRESH_EXPIRY = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days in the future
//const JWT_EXPIRY     = '7d'; //7 days

const JWT_EXPIRY 		= process.env.JWT_EXPIRY;
const REFRESH_EXPIRY 		= process.env.JWT_REFRESH_EXPIRY;

const MAX_ATTEMPTS = 3;
const LOCKOUT_DURATION = 60 * 60 * 1000; // 1 hour in milliseconds

const CAPTCHA_SECRET   = process.env.CAPTCHA_SECRET;
const CAPTCHA_SITE_KEY = process.env.CAPTCHA_SITE_KEY;

//console.log('process.env.DATABASE_URL = ' + process.env.DATABASE_URL);

console.log('pool = ' + pool);

// Register a new user
exports.registerUser = async (req, res) => {
    // Register user endpoint
    
    console.log('register\n');
	
	const { username, password, androidId, sector, branch } = req.body;

	console.log('register : username : ', username, ' password : ', password, ' androidId : ', androidId, ' sector : ', sector, ' branch : ', branch);
	
    try {
        // Check if user already exists
        const existingUser = await pool.query('SELECT * FROM users_notification WHERE username = $1', [username]);
		
		console.log('registerUser : existingUser : ', existingUser);
		
		console.log('registerUser : existingUser.rows.length  : ', existingUser.rows.length );
        
		if ((existingUser.rows.length != 0 ) && (existingUser.rows.length > 0)) {
                    onsole.log('register : the user already exists');
		    return res.status(400).json({ message: 'Username already exists' });
                 }

	/*
	// Check if device androidId already exists
        const deviceId = await pool.query('SELECT android_id FROM users_notification WHERE android_id = $1', [androidId]);
        if ((deviceId.rows.length != 0) && (deviceId.rows.length > 0)) {
            console.log('deviceId : the androidId already exists');
			return res.status(400).json({ message: 'Unauthorized login username' });
        }
	*/	
		
        // Hash the password
        const saltRounds     = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Store user in database
        result = await pool.query('INSERT INTO users_notification (username, password, android_id, sector, branch)' + 
		                          ' VALUES ($1, $2, $3, $4, $5) RETURNING id', [username, hashedPassword, androidId, sector, branch]);
		
	//console.log('register : result : ',result);
		
        // Get the generated id from the result
        const userId = result.rows[0].id;
		
		
        // Simulate a user object after registration
        const user = { id: userId, username: username, sector: sector, branch: branch };

		// Generate a JWT for the registered user
		const jwt_token = jwt.sign(
			{ userId: user.id, username: user.username }, // Payload
			JWT_SECRET, // Secret key
			{ expiresIn: JWT_EXPIRY } // Token expiry 1 day
		);
		
		//save jwt Token
		const save_jwt_token = await saveJWTToken(user, jwt_token);
		
		console.log('registered : jwt_token : ' + jwt_token);
		
		// Generate Refresh token
		const refresh_token = await handleRefreshTokenGeneration(user);
		console.log('registered : refresh_token : ' + refresh_token);

		// Send back the 'jwt token' and 'refresh' token along with a success message
		res.status(200).json({ 
			message: 'User registered successfully', 
			jwt_token: jwt_token,
			refresh_token: refresh_token,
			refresh_expiry: REFRESH_EXPIRY
		});
		
		console.error('registered successfully');
		
    } catch (error) {
        console.error('registered failure : ' + error);
        res.status(500).json({ message: 'Server error' });
    }
};

	// Save jwt token to database for a user
	async function saveJWTToken(user, jwt_token) {
		// Assuming you have a database table for jwt tokens associated with users
		// Save the jwt token with an expiration time (e.g., 1 hour)
		
		console.log('registered : store jwt token');
		
		try{
			const result = await pool.query('INSERT INTO jwt_tokens (user_id, jwt_token, username) VALUES ($1, $2, $3) RETURNING id', [
				user.id,
				jwt_token,
				user.username	
			]);
			
			console.log('registered : store jwt token : result.rows.id : ' + result.rows[0].id); //Object.keys(result.rows));
		
		}catch(error){
			console.error('registered : store jwt token : failure : ' + error);
		}
	}
	
	// Function to generate a random refresh token
	function generateRefreshToken() {
		// Create a random string of 64 characters
		const refreshToken = crypto.randomBytes(64).toString('hex');
    return refreshToken;
}

	// Save refresh token to database for a user
	async function storeRefreshTokenInDatabase(user, refreshToken) {
		// Assuming you have a database table for refresh tokens associated with users
		// Save the refresh token with an expiration time (e.g., 30 days)
		console.log('storeRefreshTokenInDatabase date : ', new Date(Date.now() + 30 * 24 * 60 * 60 * 1000));
		try{
			await pool.query('INSERT INTO refresh_tokens (user_id, refresh_token, expires_at) VALUES ($1, $2, $3)', [
				user.id,
				refreshToken,
				new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days in the future
			]);
		}catch(error){
		console.error('registered : store refresh token : failure : ' + error);
	}
}

	// Generate and store refresh token and store it db
	async function handleRefreshTokenGeneration(user) {
			const refreshToken = generateRefreshToken();
			await storeRefreshTokenInDatabase(user, refreshToken);
			return refreshToken;
	}

// Get user by ID
exports.getUser = async (req, res) => {
  const userId = req.params.id;
  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error retrieving user' });
  }
};

// Update user by ID
exports.updateUser = async (req, res) => {
  const userId = req.params.id;
  const { username, password } = req.body;
  try {
    await pool.query('UPDATE users SET username = $1, password = $2 WHERE id = $3', [username, password, userId]);
    res.json({ message: 'User updated successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error updating user' });
  }
};
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Login a user
exports.loginUser = async (req, res) => {
    const { username, password } = req.body;
	
    console.log('loginUser : username : ', username, ' password : ', password);
	
    try {
        // Check if the user exists
        const userResult = await pool.query('SELECT * FROM users_notification WHERE username = $1', [username]);

		console.log('(userResult.rows.length === 0) : ', (userResult.rows.length === 0));

        if (userResult.rows.length === 0) {
            return res.status(400).json({ message: 'Invalid username or password' });
        }

        const user = userResult.rows[0];

        // Compare the password with the hashed password stored in the database
        const passwordMatch = await bcrypt.compare(password, user.password);
		
		console.log('passwordMatch : ', passwordMatch);
		
		if (!passwordMatch) {
			// Increase failed attempts count
			let failedAttempts = user.failed_attempts + 1;

			if (failedAttempts >= MAX_ATTEMPTS) {
				console.log('!passwordMatch : failedAttempts : ', failedAttempts, ' MAX_ATTEMPTS : ', MAX_ATTEMPTS);
				const lockoutUntil = new Date(Date.now() + LOCKOUT_DURATION);
				await pool.query('UPDATE users_notification SET failed_attempts = $1, lockout_until = $2 WHERE username = $3', [failedAttempts, lockoutUntil, username]);
				//return { error: "Account locked due to too many failed attempts. Try again in 1 hour." };
				return res.status(400).json({ error: "Account locked due to too many failed attempts. Try again in 1 hour." });
			} else {
				console.log('!passwordMatch : failedAttempts : ', failedAttempts, ' MAX_ATTEMPTS : ', MAX_ATTEMPTS);
				await pool.query('UPDATE users_notification SET failed_attempts = $1 WHERE username = $2', [failedAttempts, username]);
				//return { error: `Invalid credentials. You have ${MAX_ATTEMPTS - failedAttempts} attempts remaining.` };
				return res.status(400).json({ error: `Invalid credentials. You have ${MAX_ATTEMPTS - failedAttempts} attempts remaining.` });
			}
		}
		
		console.log('passwordMatch');
        
		//if (!passwordMatch) {
        //    return res.status(400).json({ message: 'Invalid username or password' });
        //}

		// If password is correct, reset failed attempts and lockout
		await pool.query('UPDATE users_notification SET failed_attempts = 0, lockout_until = NULL WHERE username = $1', [username]);


        // Generate JWT tokens and refresh tokens.
        const jwt_token = jwt.sign({ userId: user.id }, JWT_SECRET , { expiresIn: JWT_EXPIRY });
        
		//Generate a random refresh token
		//const refreshToken = jwt.sign({ userId: user.id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });
		
		// Generate Refresh token and store it in db
		const refresh_token = await handleRefreshTokenGeneration(user);
		console.log('registered : refresh_token : ' + refresh_token);


        // Optionally store the refresh token in the database or send it to the client
        //await pool.query('INSERT INTO refresh_tokens (user_id, refresh_token) VALUES ($1, $2)', [user.id, refreshToken]);

        // Send jwt token, refresh token and refresh token to the client
        res.status(200).json({ jwt_token:jwt_token, refresh_token:refresh_token, refresh_expiry: REFRESH_EXPIRY});
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
};
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//verify captcha
 exports.verifyCaptcha = async (req, res) => {
    const captchaToken = req.body.captcha_token;
    
	//console.log('verifyCaptcha : captchaToken : ' + captchaToken);
	 
	 try {
        // Send the token to the CAPTCHA provider (hCaptcha, reCAPTCHA) for verification
        /*
	//solution 1
	const response = await axios.post('https://hcaptcha.com/siteverify', null, {
            params: {
                secret: CAPTCHA_SECRET,   // Your secret key for CAPTCHA verification
                response: captchaToken    // The token received from the client
            }
        });
	*/
	
	//solution 2
	const response = await axios.post(
            'https://hcaptcha.com/siteverify',
            new URLSearchParams({
                secret: CAPTCHA_SECRET,
                response: captchaToken,
            }).toString(),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
            }
        );

/*
//solution 3
const VERIFY_URL = "https://api.hcaptcha.com/siteverify"

// Build payload with secret key and token.
data = { 'secret': CAPTCHA_SECRET, 'response': captchaToken }

// Make POST request with data payload to hCaptcha API endpoint.
response = http.post(url=VERIFY_URL, data=data)

//Parse JSON from response. Check for success or error codes.
response_json = JSON.parse(response.content)	
*/
	
console.log('verify captcha : ', response.data); // Check for errors or unexpected responses
	
        // Check if CAPTCHA verification was successful
        if (response.data.success) {
	    console.log('verify captcha : success');
            return res.status(200).json({ success: true });
        } else {
	    console.error('verify captcha : failed');
            return res.status(400).json({ success: false, message: 'CAPTCHA verification failed' });
        }
		 
    } catch (error) {
        console.error('verify captcha : error : ', error);
        return res.status(500).json({ success: false, message: 'Server error from HCaptcha' });
    }
};
