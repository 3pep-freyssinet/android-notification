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
const pool       = require('../db'); // Assuming you use a database pool for Postgres or MySQL
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const crypto     = require('crypto');
const axios      = require('axios');
const http       = require('http');
const nodemailer = require('nodemailer');

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

const YAHOO_USER = process.env.YAHOO_USER;
const YAHOO_PASS = process.env.YAHOO_PASS;

const EMAIL_FROM = process.env.EMAIL_FROM;
const EMAIL_TO   = process.env.EMAIL_TO;


//console.log('process.env.DATABASE_URL = ' + process.env.DATABASE_URL);

console.log('pool = ' + pool);

/* get expiry date from jwt token ****************
const jwt = require('jsonwebtoken');

// Example JWT token (replace with the actual token)
const token = 'your.jwt.token';

// Decode the token without verification
const decoded = jwt.decode(token);

if (decoded && decoded.exp) {
  // Convert the expiry time to a human-readable format
  const expiryDate = new Date(decoded.exp * 1000);
  console.log('Token expires at:', expiryDate);
} else {
  console.log('Could not retrieve expiration date from token');
}

*/


//update FirebaseId
 exports.updateFirebaseId = async (req, res) => {	
  console.log('updateFirebaseId : start');

  const { androidId, firebaseId } = req.body 
  console.log('updateFirebaseId : androidId : ', androidId, ' firebaseId : ', firebaseId);
	 
 const userId = req.resolvedUserId;
 console.log('updateFirebaseId : userId : ', userId);
	 
 try {	 	 
    // Update only if firebase_id is NULL
    const result = await pool.query(
      `UPDATE users_notification 
       SET firebase_id = $1 
       WHERE id = $2 AND firebase_id IS NULL`,
      [firebaseId, userId]
    );

    if (result.rowCount === 0) {
      console.log('updateFirebaseId : Firebase ID already set');   
      return res.status(400).json({ 
        code: "FIREBASE_ID_ALREADY_SET",
        message: "Firebase ID already exists for this user" 
      });
    }
    
    console.log('updateFirebaseId : Firebase ID updated successfully'); 
    res.status(200).json({ success: true });
  } catch (error) {
    console.error('updateFirebaseId : Database error:', error);
    res.status(500).json({ 
      code: "SERVER_ERROR", 
      message: "Temporary server issue. Please retry." 
    });	 
 }
 }

//delete resset password token 
 exports.deleteRessetPasswordToken = async (req, res) => {	
  console.log('deleteRessetPasswordToken : start');
  const { androidId } = req.body;
	 
  console.log('deleteRessetPasswordToken : androidId : ', androidId);	
	 
  try {
    // Verify user exists
    const userResult = await pool.query('SELECT id FROM users_notification WHERE android_id = $1', [androidId]);
    if (userResult.rowCount === 0) {
      console.log('deleteRessetPasswordToken : No user found with this androidId');
      return res.status(404).json({ message: "No user found with this androidId" });
    }
    const userId = userResult.rows[0].id;
    console.log('deleteRessetPasswordToken : userId : ', userId);
	  
    //delete the token
    await pool.query(`DELETE FROM password_reset WHERE user_id = $1`, [userId]);
	  
    console.log('deleteRessetPasswordToken : Token has been successfully deleted');  
    res.status(200).json({
            success: true,
            message: "Token has been successfully deleted."
        });
  } catch (error) {
    console.error('deleteRessetPasswordToken :', error);
    //res.status(500).json({ success:false, message: "Internal server error" });
    res.status(500).json({
            success: false,
            message: "An error occurred while deleting the token.",
        });	  
  }
 }
	 
// POST /users/verify-reset-token
  exports.verifyResetToken = async (req, res) => {	
  console.log('verifyResetPassword : start');

  //used in curl
  //const token = req.query.token;
  //const userId = req.query.userId;
	  
  const { token, userId} = req.body;
  
  console.log('verifyResetPassword : token : ', token, ' userId : ', userId);
  
  // Check if token and userId are provided
  if (!token || !userId) {
    console.log('verifyResetPassword : Token and userId are required');  
    return res.status(400).json({ success: false, message: 'Token and userId are required' });
  }
  
  try {
    // Query the database for a matching token for the given user
    const query = `
      SELECT * FROM password_reset 
      WHERE user_id = $1 AND token = $2 AND expires_at > NOW()
    `;
    const result = await pool.query(query, [userId, token]);
    
    if (result.rowCount === 0) {
      // No valid token found (either invalid or expired)
      console.log('verifyResetPassword : Invalid or expired token');      
      return res.status(400).json({ success: false, message: 'Invalid or expired token' });
    }
    
    // Token is valid
    console.log('verifyResetPassword : token is valid');  
    return res.json({ success: true, message: 'Token is valid' });
  } catch (error) {
    console.error('Error verifying reset token:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};


// POST /api/reset-password
exports.resetPassword_ = async (req, res) => {
  console.log('resetPassword : start');  
res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>Password Reset Successful</title>
      </head>
      <body>
        <p>Hello the World.</p>
      </body>
      </html>
    `);
}

// POST /api/reset-password
/*
response.ok Behavior:
response.ok is true only for status codes 200-299 (successful responses).
Any other status (e.g., 402, 400, 500) sets response.ok to false.
*/

let tries = 0;

exports.resetPassword = async (req, res) => {
  console.log('resetPassword : start');  
  const { userId, token, newPassword } = req.body;
  
  /*
  //for testing, remove in production
  if(true){
  return res.status(400).json({
            success: false,
	    status:400,
            //message:'An error occurred while resetting your password.',
	    //message:'Resset password successful.',
	    //message:'server error.',
	    message:'Internal error',
	    loginLink:'myapp://login' // link to redirect to  'LoginActivity'
	   });
  }
  */
  
  console.log('resetPassword : userId : ', userId, ' token : ', token, ' newPassword : ', newPassword); 

  // Validate inputs
  if (!userId || !token) {
     console.log('resetPassword : Missing userId or token');	  
    //return res.status(400).json({ success:false, message: "Missing userId or token" });
    return res.status(400).json({
	    status:400,
	    success:false, 
	    message: 'Internal error', 
	    loginLink: 'myapp://login'
    });
  }
	
  try {
    /*	  
    // Retrieve the token entry 
    const result = await pool.query(`
      SELECT * FROM password_reset
      WHERE user_id = $1 AND token = $2`,
      [userId, token]
    );
    */
     const result = await pool.query(`
      SELECT * FROM password_reset 
     WHERE user_id = $1 AND token = $2`,
      [userId, token]
    );
	  
    if (result.rowCount === 0) {
      console.log('resetPassword : Invalid or expired token');      
      return res.status(400).json({ 
	      success:false, 
	      status:400,
	      message: "Invalid or expired token", 
	      loginLink: 'myapp://login'});
    }
	  
    // Hash the new password (using bcrypt)
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    
    //get the id from the req
    //const userId = req.user.userId;
	
    //console.log('resetPassword : userId : ', userId);
       
    //check if the new password is already used
    const isUnique = await isNewPasswordUnique(userId, newPassword, hashedNewPassword);
    if (!isUnique) {
	console.log('resetPassword : Password matches a previous/current password.'); 
            ////////////////////////////////////////////////
	//update the table 'ban_user'
	const updateBanUser = await updateBanUser({
		    userId: userId,
		    passwordTries: tries++,
		    passwordTriedAt: new Date(Date.now()),
		    startBanTime: null
	});
	
	if(!updateBanUser) throw new Error ('internal error');
	    
        //return res.status(200).json({ error: 'Password matches a previous/current password.' });
	    return res.status(200).json({
	    status:200,
            success: false,
	    message: 'Password matches a previous/current password.',
	    loginLink: 'myapp://login', // link to redirect to  'LoginActivity',
	    mainLink: 'myapp://main', // link to redirect to  'MainActivity'
        });
    }
    console.log('resetPassword : the password is unique.');
	  
    // Update the user's password in the users table
    await pool.query(`UPDATE users_notification SET password = $1 WHERE id = $2`, [hashedNewPassword, userId]);
    
    // Optionally, remove the reset token
    await pool.query(`DELETE FROM password_reset WHERE user_id = $1`, [userId]);
	  
    console.log('resetPassword : Password has been reset successfully');  
    res.status(200).json({
	    status:200,
            success: true,
            message: 'Your password has been reset successfully.',
            loginLink: 'myapp://login', // link to redirect to  'LoginActivity'
        });
	  
  } catch (error) {
    console.log('Reset Password Error:', error.message);
    //res.status(500).json({ success:false, message: 'Internal server error' });
    res.status(500).json({
            success: false,
	    status:500,
            //message: 'catch server, An error occurred while resetting your password.',
	    message: error.message,
	    loginLink: 'myapp://login' // link to redirect to  'LoginActivity',
        });	  
  }
};

/**

*/
//////////////////////////////////////////////
updateBanUser({
		    userId: userId,
		    passwordTries: tries++,
		    passwordTriedAt: new Date(Date.now()),
		    startBanTime: null
async function updateBanUser(options) {
 

}
//////////////////////////////////////////////
/**
 * Checks if a new password is unique (not reused from current/history).
 * @returns {Promise<boolean>} true if password is unique, false if it's a duplicate.
 */
async function isNewPasswordUnique(userId, newPassword) {
  try {
    // 1. Fetch current password
    const userQuery = `
      SELECT password 
      FROM users_notification 
      WHERE id = $1
    `;
    const userResult = await pool.query(userQuery, [userId]);
    const storedPassword = userResult.rows[0]?.password;

    if (!storedPassword) {
      throw new Error('User not found');
    }

    // 2. Fetch password history
    const historyQuery = `
      SELECT password 
      FROM password_history 
      WHERE user_id = $1
    `;
    const historyResult = await pool.query(historyQuery, [userId]);
    const previousPasswords = historyResult.rows.map(row => row.password);

    // 3. Compare new password against current + history
    for (const hash of [storedPassword, ...previousPasswords]) {
      if (await bcrypt.compare(newPassword, hash)) {
        console.error('isNewPasswordUnique : Password matches a previous/current password.');
        return false; // Password is NOT unique
      }
    }

    console.log('isNewPasswordUnique : Password is unique.');
    return true; // Password is unique

  } catch (error) {
    console.error('Validation failed:', error.message);
    return false; // Fail-safe: Treat errors as invalid
  }
}


// POST /users/forgot-password
exports.forgotPassword_ = async (req, res) => {
 console.log('forgotPassword : start');	
res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Password Reset Successful</title>
    </head>
    <body>
      <p>Your password has been reset successfully.</p>
      <p>Redirecting to login...</p>
      <script>
        window.location.href = "myapp://login";
      </script>
    </body>
    </html>
  `);
}


// POST /users/forgot-password
exports.forgotPassword__ = async (req, res) => {
  console.log('forgotPassword : start');
  const { email } = req.body;
try{
	console.log('forgotPassword : start');
	res.setHeader('Content-Type', 'text/html');	
	res.send(`
	    <!DOCTYPE html>
	    <html>
	    <head>
	      <meta charset="UTF-8">
	      <title>Password Reset Successful</title>
	    </head>
	    <body>
	      <p>Your password has been reset successfully.</p>
              <p><a href="myapp://login">Retour à la page de connexion (Deep Link)</a></p>
	      <br><br><br><br><br>
              <button onclick="Android.openLoginActivity()">Retour à la page de connexion (JavaScript Interface)</button>
	    </body>
	    </html>
	  `);
} catch (error) {
	console.error('Erreur dans forgotPassword:', error);
	res.status(500).send('Erreur interne du serveur');
}
};

exports.forgotPassword = async (req, res) => {
  console.log('forgotPassword : start');
  const { email } = req.body;
  try {
    // Verify user exists
    const userResult = await pool.query('SELECT id FROM users_notification WHERE email = $1', [email]);
    if (userResult.rowCount === 0) {
      return res.status(404).json({ message: 'No user found with this email' });
    }
    const userId = userResult.rows[0].id;

    // Generate a reset token and set expiration (e.g., 1 hour)
    const resetToken = crypto.randomBytes(32).toString('hex');
    const tokenExpiry = new Date(Date.now() + 3600000); // 1 hour from now

    // Save token to database (create a "password_reset" table if not exists)
    await pool.query(`
      INSERT INTO password_reset (user_id, token, expires_at)
      VALUES ($1, $2, $3)
      ON CONFLICT (user_id) DO UPDATE SET token = $2, expires_at = $3
    `, [userId, resetToken, tokenExpiry]);

    // Send reset email using nodemailer (configure your transporter)

    //Google mail
    const transporter = nodemailer.createTransport({
      // e.g., SMTP configuration or a service like SendGrid
      service: 'gmail',
      //auth: { user: 'your-email@gmail.com', pass: 'your-password' }
      auth: { user: 'beldi.chergui@gmail.com', pass: 'qikixyramfonftcs' }
    });
    
   
  /*
  //Yahoo mail
  const transporter = nodemailer.createTransport({
  host: 'smtp.mail.yahoo.com',
  port: 465, // Use 465 for SSL; use 587 for TLS if preferred
  secure: true, // true for port 465, false for port 587
  auth: {
    user: 'tomcat.user@yahoo.co.in', //process.env.YAHOO_USER, // your Yahoo email address, e.g., 'your-email@yahoo.com'
    pass: 'faddafadda',            //process.env.YAHOO_PASS  // your Yahoo app password (if using 2FA)
  }
});
*/
    //if(true)res.json({ message: 'Password reset email sent' });
	  
    const resetLink = `https://android-notification.onrender.com/reset-password?token=${resetToken}&userId=${userId}`;
    //const email_ = 'tomcat.super@yahoo.fr';
    await transporter.sendMail({
      //from: '"Your App" <beldi.chergui@gmail.com>',
      from: '"Android Notification " <' + EMAIL_FROM + '>',
      to: EMAIL_TO, //EMAIL_,
      subject: 'Password Reset Request',
      text: `Click the link to reset your password: ${resetLink}`,
      //html: `<p>Click the link to reset your password: <a href="${resetLink}">${resetLink}</a></p>`
      html: `<p>Click the link to reset your password : <a href="${resetLink}">link</a></p>`
    });
	  
     console.log('forgotPassword : Password reset email sent');
    res.json({ message: 'Password reset email sent' });
  } catch (error) {
    console.error('Forgot Password Error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

exports.forgotPassword_ = async (req, res) => {
 console.log('forgotPassword : start');	
res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Password Reset Successful</title>
    </head>
    <body>
      <p>Your password has been reset successfully.</p>
      <p>Redirecting to login...</p>
      <script>
        window.location.href = "myapp://login";
      </script>
    </body>
    </html>
  `);
}

// Register a new user
exports.registerUser = async (req, res) => {
    // Register user endpoint
    
    console.log('register\n');
	
	const { username, password, androidId, firebaseId, sector, branch } = req.body;

	console.log('register : username : ', username, ' password : ', password, ' androidId : ', androidId, ' firebaseId : ', firebaseId, ' sector : ', sector, ' branch : ', branch);
	
    try {
        // Check if user already exists
        const existingUser = await pool.query('SELECT * FROM users_notification WHERE username = $1', [username]);
		
		//console.log('registerUser : existingUser : ', existingUser);
		
		console.log('registerUser : existingUser.rows.length  : ', existingUser.rows.length );
        
		if ((existingUser.rows.length != 0 ) && (existingUser.rows.length > 0)) {
                    console.log('register : the user already exists');
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
        result = await pool.query('INSERT INTO users_notification (username, password, android_id, firebaseId, sector, branch)' + 
		                          ' VALUES ($1, $2, $3, $4, $5, $6) RETURNING id', [username, hashedPassword, androidId, firebaseId || null, sector, branch]);

	if (result.rows.length == 0 ) {
                    console.error('register : cannot register the user');
		    return res.status(400).json({ message: 'cannot register the user' });
                 }  
	    
	//console.log('register : result : ', result);
		
        // Get the generated id from the result
        const userId = result.rows[0].id;
	console.log('register : userId : ', userId);
		
        // Simulate a user object after registration
        const user = { id: userId, username: username, sector: sector, branch: branch };

	//handle the creation and storing the JWT and REFRESH token.
	const{jwt_token, refresh_token, refresh_expires_at} = await handleTokens(user);
	    
	console.log('jwt_token : ', jwt_token, ' refresh_token : ', refresh_token, ' refresh_expires_at : ', refresh_expires_at)
	
	/*
	//current date
	const now = Date.now();

	//created at
	const created_at = new Date(now);

	//JWT expiration date
	const expiryDays = parseInt(JWT_EXPIRY.replace('d', ''), 10); // The radix '10' specifies the base for parsing.
	console.log('register : JWT expiryDays : ', expiryDays); 
	    
	const jwt_expires_at = new Date(now + expiryDays * 24 * 60 * 60 * 1000);
	console.log('register : jwt_expires_at : ', jwt_expires_at);

	//REFRESH expiration date
	const expiryDays_ = parseInt(REFRESH_EXPIRY.replace('d', ''), 10); // The radix '10' specifies the base for parsing.
	console.log('register : REFRESH expiryDays : ', expiryDays_); 
	    
	const refresh_expires_at = new Date(now + expiryDays_ * 24 * 60 * 60 * 1000);
	console.log('register : refresh_expires_at : ', refresh_expires_at);
	    
	// Generate a JWT for the registered user
	const jwt_token = jwt.sign(
		{ userId: user.id, username: user.username }, 	// Payload
		JWT_SECRET, 					// Secret key
		{ expiresIn: JWT_EXPIRY } 			// Token expiry
	);
		
	//save jwt Token in database
	const save_jwt_token = await saveJWTToken(user, jwt_token, created_at, jwt_expires_at);
	
	console.log('registered : jwt_token : ', jwt_token, ' created_at : ', created_at, ' expires_at : ', jwt_expires_at);
	    
	// Generate Refresh token
	const refresh_token = await generateRefreshToken();
	console.log('registered : refresh_token : ', refresh_token, ' refresh_created_at : ', created_at, ' refresh_expires_at : ', refresh_expires_at);

	/*
	const refresh_expiryDays = parseInt(REFRESH_EXPIRY.replace('d', ''), 10); // '10' is the base parsing
	console.log('registered : refresh_expiryDays : ', refresh_expiryDays);
	
	const refresh_expires_at = new Date(Date.now() + refresh_expiryDays * 24 * 60 * 60 * 1000);
	
	console.log('registered before call : refresh_expires_at : ', refresh_expires_at);
	*/
	 /*   
	//save refresh Token in database
	const save_refresh_token = await storeRefreshTokenInDatabase(user, refresh_token, created_at, refresh_expires_at);
	    
       console.log('registered : user : ', user, ' refresh_token : ', refresh_token, ' expires_at : ', refresh_expires_at);
	*/
	    
	// Send back the 'jwt token' and 'refresh' token along with a success message
	res.status(200).json({ 
		message: 'User registered successfully', 
		jwt_token: jwt_token,
		refresh_token: refresh_token,
		refresh_expiry: refresh_expires_at
	});
	
	console.error('registered successfully');
		
    } catch (error) {
        console.error('registered failure : ' + error);
        res.status(500).json({ message: 'Server error' });
    }
};

//check credentials (username, password)
exports.checkCredentials = async (req, res) => {
   try{ 
   console.log('checkCredentials\n');
   const { createSession } = require('../services/passwordChangeService');
    
   console.log('checkCredentials : createSession :', createSession,'\n');

    const {username, password } = req.body;
    console.log('checkCredentials : username : ', username, ' password : ', password);
	 
    //Get the id knowing the 'username'
    const userId = await getUserId__(username);
    if(userId == null){
	   console.warn('User not found for username:', username);
           return res.status(404).json({ message: 'User not found' });
    }
    console.log('checkCredentials : userId : ', userId);
    
    // Fetch stored password hash and last changed date
    const userQuery = `
        SELECT password, last_password_changed 
        FROM users_notification 
        WHERE id = $1
    `;
    const userResult     = await pool.query(userQuery, [userId]);
    const storedPassword = userResult.rows[0]?.password;
	   
    //check the validity of the provided current password 'current password' against the stored password 'stored password'.
    // Compare the provided clear current password with the hashed password stored in the database.

	const isPasswordValid = await bcrypt.compare(password, storedPassword);
         
	console.log('checkCredentials : isPasswordValid : ', isPasswordValid);
		
        if (!isPasswordValid) {
            return res.status(400).json({ message: 'Invalid username or password' });
        }
	  console.log('checkCredentials : Password is valid.');

	// Create a password change session
        const sessionId = await createSession(userId);

        // Respond with the session ID
        return res.status(200).json({ message: 'Credentials verified', sessionId:sessionId });
    
	 //return res.status(200).json({ success: true, message: 'Password is valid.' });  
  }catch(error){
	console.error('checkCredentials : ' + error);
        res.status(500).json({ message: 'Server error' });
  }   
}

//get change password session progress
exports.getChangePasswordSessionProgress = async (req, res) => {
    console.log('getChangePasswordSessionProgress : Start...');
    const { sessionId } = req.query;
    console.log('checkPasswordSession : sessionId : ', sessionId);
    if (!sessionId) {
        console.log('getChangePasswordSessionProgress : Session ID required');
	return res.status(400).json({ message: "Session ID required" });
    }

    const result = await pool.query( //'is_new_password_verified' not used
        `SELECT is_authenticated, is_new_password_verified, is_new_password_applied 
         FROM password_change_sessions WHERE session_id = $1`,
        [sessionId]
    );

    if (result.rowCount === 0) {
         console.log('getChangePasswordSessionProgress : Session not found');
	return res.status(404).json({ message: "Session not found" });
    }
    
    console.log('getChangePasswordSessionProgress : is_authenticated : ', result.rows[0].is_authenticated, ' is_new_password_verified : ', result.rows[0].is_new_password_verified, ' is_new_password_applied : ', result.rows[0].is_new_password_applied);
    res.status(200).json(result.rows[0]);
};


//clear change password session
exports.clearChangePasswordSession = async (req, res) => {
    const userId = req.user.userId;
    console.log('clearChangePasswordSession : userId : ', userId);
    if (!userId) {
        return res.status(400).json({ message: "userId not found" });
    }
    try {
        await pool.query(
            "DELETE FROM password_change_sessions WHERE user_id = $1",
            [userId]
        );
	console.log('clearChangePasswordSession : Password change session cleared');    
        res.status(200).json({ message: "Password change session cleared" });
    } catch (error) {
        console.error("Error clearing session:", error);
        res.status(500).json({ message: "Internal server error" });
    }
}

//checkChangePasswordSession
exports.checkChangePasswordSession = async (req, res) => {
    const { sessionId } = req.query;
    const userId        = req.user.userId;
    console.log('checkChangePasswordSession : sessionId : ', sessionId,  ' userId : ', userId);
    if (!sessionId) {
        return res.status(400).json({ message: "Session ID is required" });
    }

    try {
        const session = await pool.query(
            //"SELECT * FROM password_change_sessions WHERE session_id = $1 AND user_id = $2 AND is_new_password_applied = false",
	    "SELECT * FROM password_change_sessions WHERE session_id = $1 AND user_id = $2",
            [sessionId, userId]
        );

	if(!session.rowCount > 0){
		console.log('checkChangePasswordSession : session error.');
		return res.status(400).json({ message: "session error." });
	}
	console.log('checkChangePasswordSession : session : ', session);
	    
        //res.json({ hasActiveSession: session.rowCount > 0 });
	console.log('checkChangePasswordSession : is_authenticated : ', session.rows[0].is_authenticated, ' is_new_password_applied : ', session.rows[0].is_new_password_applied);    
	res.json({ isAuthenticated: session.rows[0].is_authenticated,
		   isNewPasswordApplied:session.rows[0].is_new_password_applied});  
	 } catch (error) {
        console.error("Error checking password session:", error);
        res.status(500).json({ message: "Internal server error" });
    }
}

//check change password session : if the change password session is completed or not
exports.checkPasswordSession = async (req, res) => {
    console.log('checkPasswordSession : Start...');
    const { sessionId } = req.query;
    console.log('checkPasswordSession : sessionId : ', sessionId);
    if (!sessionId) {
        console.log('checkPasswordSession : sessionId : Session ID required');
	return res.status(400).json({ message: "Session ID required" });
    }

    const result = await pool.query(
        "SELECT * FROM password_change_sessions WHERE session_id = $1 AND is_new_password_applied = false",
        [sessionId]
    );

    if (result.rowCount === 0) {
	console.log('checkPasswordSession : No active session found');    
        return res.status(404).json({ message: "No active session found" });
    }

    res.status(200).json({ message: "Session is active" });
};

//update password. apply change password. replace the current password by the supplied new password.
exports.updatePassword = async (req, res) => {
   try{ 
    console.log('updatePassword\n');
	
    const { sessionId, password } = req.body;
    console.log('updatePassword : sessionId:', sessionId, ' password : ', password);

    // Retrieve the session from the database
    const sessionQuery = `
        SELECT * FROM password_change_sessions WHERE session_id = $1
    `;
    const sessionResult = await pool.query(sessionQuery, [sessionId]);

    if (sessionResult.rowCount === 0) {
      return res.status(404).json({ message: 'Session not found.' });
    }

    const session = sessionResult.rows[0];

    // Check if session is expired
    if (new Date(session.expiration) < new Date()) {
      return res.status(401).json({ message: 'Session expired.' });
    }
   
    //get the id from the req
    const userId = req.user.userId;
	
    console.log('updatePassword : userId : ', userId);

    // Fetch stored password hash and last changed date
    const userQuery = `
        SELECT password, last_password_changed 
        FROM users_notification 
        WHERE id = $1
    `;
    const userResult     = await pool.query(userQuery, [userId]);
    const storedPassword = userResult.rows[0]?.password;
    
    // Update password and record history
    const newHash = await bcrypt.hash(password, 10);
    const updateQuery = `
        UPDATE users_notification 
        SET password = $1, last_password_changed = NOW() 
        WHERE id = $2
    `;
    await pool.query(updateQuery, [newHash, userId]);

    // Insert old password into history
    const insertHistoryQuery = `
        INSERT INTO password_history (user_id, password) 
        VALUES ($1, $2)
    `;
    await pool.query(insertHistoryQuery, [userId, storedPassword]);
	   
    console.log('updatePassword : Password updated successfully.');
	   
   // Update the session to reflect that the new password has been applied
    await updateSession(sessionId, { is_new_password_applied: true });

    console.log('updatePassword: Password updated and session marked as completed.');
    return res.status(200).json({ message: 'Password updated successfully.' });
  
   }catch(error){
	console.error('updatePassword : ' + error);
        res.status(500).json({ message: 'Server error' });
  }   
}

//match password. check, if the provided password match the previous password.
//store new password.
exports.matchPassword = async (req, res) => {
   try{ 
    console.log('matchPassword\n');
    const { updateSession  } = require('../services/passwordChangeService'); //needed below

     //for test
     //if(true)return res.status(400).json({ message: 'SessionId or password are required.' });   
     //if(true)return res.status(404).json({ message: 'Session not found.' });
     //if(true)return res.status(401).json({ message: 'Session expired.' });
     //if(true)return res.status(402).json({ message: 'New password cannot be the same as the current or previous passwords.' });
     //if(true)return res.status(200).json({ message: 'Password verified successfully.' });
     //if(true)res.status(500).json({ message: 'Server error. Please, try again later.' });

	   
    const { sessionId, password } = req.body;

    if (!sessionId || !password) {
	    console.error('SessionId or password are required.');
            return res.status(400).json({ message: 'SessionId or password are required.' });
     }
	   
    console.log('matchPassword : sessionId : ', sessionId, ' password : ', password);

     // Retrieve the 'session' from the database
     const sessionQuery = `
            SELECT * FROM password_change_sessions WHERE session_id = $1
        `;
     const sessionResult = await pool.query(sessionQuery, [sessionId]);
     if (sessionResult.rowCount === 0) {
            return res.status(404).json({ message: 'Session not found.' });
     }

     const session = sessionResult.rows[0];

     // Check if session is expired
     if (new Date(session.expiration) < new Date()) {
            return res.status(401).json({ message: 'Session expired.' });
     }  
	   
    /*
    //hash the password
    const passwordHash = await bcrypt.hash(password, 10);
	   
    //Get the id knowing the 'username'
    const userId = await getUserId__(username);
    if(userId == null){
	   console.warn('User not found for username:', username);
           return res.status(404).json({ message: 'User not found' });
    }
    console.log('matchPassword : req.user : ', req.user);
    
    */   
    //get the id from the req
    const userId = req.user.userId;
	
    console.log('matchPassword : userId : ', userId);
    
    // Fetch stored password hash and last changed date
    const userQuery = `
        SELECT password, last_password_changed 
        FROM users_notification 
        WHERE id = $1
    `;
    const userResult     = await pool.query(userQuery, [userId]);
    const storedPassword = userResult.rows[0]?.password;

    /*
    //check the validity of the provided current password 'current password' against the stored password 'stored password'.
    // Compare the provided clear current password with the hashed password stored in the database.

	const isPasswordValid = await bcrypt.compare(password, storedPassword);
         
	console.log('matchPassword : isPasswordValid : ', isPasswordValid);
		
        if (!isPasswordValid) {
            return res.status(400).json({ message: 'Invalid username or password' });
        }
	*/
	   
    // Get all password stored in 'password_history'. 
    const historyQuery = `
        SELECT password 
        FROM password_history 
        WHERE user_id = $1
    `;
    const historyResult    = await pool.query(historyQuery, [userId]);
    const previousPassword = historyResult.rows.map(row => row.password);

    for (const hash of [storedPassword, ...previousPassword]) { //'storedPassword' is the cuurent password
	console.log('matchPassword : loop : hash : ', hash, ' password : ', password); 
	 const test =  await bcrypt.compare(password, hash);//compare clear with hash
	 console.log('matchPassword : loop : test : ', test);    
        if (await bcrypt.compare(password, hash)) {
            //throw new Error('New password cannot be the same as the current or previous passwords.');
	    console.error('matchPassword : New password cannot be the same as the current or previous passwords.');
	    return res.status(202).json({ message: 'New password cannot be the same as the current or previous passwords.' });
        }
    }
     console.log('matchPassword : Password is valid.');

     //store the new password
     /*
     // Fetch stored password hash and last changed date
    const userQuery = `
        SELECT password, last_password_changed 
        FROM users_notification 
        WHERE id = $1
    `;
    const userResult     = await pool.query(userQuery, [userId]);
    const storedPassword = userResult.rows[0]?.password;
    */
	   
    // Update password and record history
    const newHash = await bcrypt.hash(password, 10);
    const updateQuery = `
        UPDATE users_notification 
        SET password = $1, last_password_changed = NOW() 
        WHERE id = $2
    `;
    await pool.query(updateQuery, [newHash, userId]);

    // Insert old password into history
    const insertHistoryQuery = `
        INSERT INTO password_history (user_id, password) 
        VALUES ($1, $2)
    `;
    await pool.query(insertHistoryQuery, [userId, storedPassword]);
	   
    console.log('matchPassword : Password updated successfully.');
	   
   // Update the session to reflect that the new password has been applied
    await updateSession(sessionId, { is_new_password_applied: true });
    
    //if(updateSession_)return res.status(403).json({ message: 'Password updated failure. Session cannot updated.' });
	    
     console.log('matchPassword : session updated successfully. Password verified successfully ');
     return res.status(200).json({ message: 'Password verified successfully.' });
     
   }catch(error){
	console.error('matchPassword : ' + error);
        res.status(500).json({ message: 'Server error' });
  }   
}

//change pwd : replace the current password by the new password.
exports.changePassword = async (req, res) => {
   try{ 
    console.log('changePassword\n');
	
    const {username, currentPassword, newPassword } = req.body;
    console.log('changePassword : username : ', username, ' currentPassword : ', currentPassword, ' newPassword : ', newPassword);
	 
    //Get the id knowing the 'username'
    const userId = await getUserId__(username);
    if(userId == null){
	   console.warn('User not found for username:', username);
           return res.status(404).json({ message: 'User not found' });
    }
    console.log('changePassword : userId : ', userId);
   
    //if(true)return;
	   
    // Fetch stored password hash and last changed date
    const userQuery = `
        SELECT password, last_password_changed 
        FROM users_notification 
        WHERE id = $1
    `;
    const userResult     = await pool.query(userQuery, [userId]);
    const storedPassword = userResult.rows[0]?.password;

    //check the validity of the provided current password 'current password' against the stored password 'stored password'.
    // Compare the provided clear current password with the hashed password stored in the database.
        //console.log('************************************************');
	//console.log('test password : ', currentPassword == 'NAme147@');
	// Hash the current password
	//const hashedPassword = await bcrypt.hash('NAme147@', 10);
        //console.log('encypted password  : ', hashedPassword);

        const saltRounds     = 10;
        const hashedCurrentPassword = await bcrypt.hash(currentPassword, saltRounds);   
        
	//const isMatch1 = await bcrypt.compare('NAme147@', hashedPassword);
	const isMatch2 = await bcrypt.compare(currentPassword, hashedCurrentPassword); 
	
	//console.log('test isMatch1 : ', isMatch1, ' isMatch2 : ', isMatch2);
	//console.log('************************************************');
        //console.log('changePassword : before crypt : ', currentPassword, ' currentPassword hashed : ', hashedCurrentPassword);
	//console.log('changePassword : storedPassword : ', storedPassword); 
	
	const isPasswordValid = await bcrypt.compare(currentPassword, storedPassword);
         
	console.log('changePassword : isPasswordValid : ', isPasswordValid);
		
        if (!isPasswordValid) {
            return res.status(400).json({ message: 'Invalid username or password' });
        }

    //Here the provided current password is valid. Check if the new password matches the current or previous passwords
    // Get all password stored in 'password_history'. 
    const historyQuery = `
        SELECT password 
        FROM password_history 
        WHERE user_id = $1
    `;
    const historyResult    = await pool.query(historyQuery, [userId]);
    const previousPassword = historyResult.rows.map(row => row.password);

    for (const hash of [storedPassword, ...previousPassword]) {
	console.log('changePassword : loop : hash : ', hash); 
	const test = await bcrypt.compare(newPassword, hash);
	console.log('changePassword : loop : test : ', test); 
        if (await bcrypt.compare(newPassword, hash)) {
            //throw new Error('New password cannot be the same as the current or previous passwords.');
	    console.error('changePassword : New password cannot be the same as the current or previous passwords. '); 
	    return res.status(401).json({ message: 'New password cannot be the same as the current or previous passwords.' });
        }
    }
    console.log('changePassword : after for loop'); 
    // Update password and record history
    const newHash = await bcrypt.hash(newPassword, 10);
    const updateQuery = `
        UPDATE users_notification 
        SET password = $1, last_password_changed = NOW() 
        WHERE id = $2
    `;
    await pool.query(updateQuery, [newHash, userId]);

    // Insert old password into history
    const insertHistoryQuery = `
        INSERT INTO password_history (user_id, password) 
        VALUES ($1, $2)
    `;
    await pool.query(insertHistoryQuery, [userId, storedPassword]);
	   
    console.log('changePassword : Password changed successfully.');
	   
    //return { success: true, message: 'Password changed successfully.' };
    return res.status(200).json({ success: true, message: 'Password changed successfully.' });  
  }catch(error){
	console.error('changePassword : ' + error);
        res.status(500).json({ message: 'Server error' });
  }
}

// Save jwt token to database for a user
async function saveJWTToken(user, jwt_token, created_at, expire_at) {
	// Assuming you have a database table for jwt tokens associated with users
	
	console.log('registered : store jwt token');
		
		try{
			/*
			const result = await pool.query('INSERT INTO jwt_tokens (user_id, jwt_token, username) VALUES ($1, $2, $3) RETURNING id', [
				user.id,
				jwt_token,
				user.username	
			]);
			*/
			
			const result = await pool.query(`
  			INSERT INTO jwt_tokens (user_id, jwt_token, username, last_updated, expire_at)
  			VALUES ($1, $2, $3, $4, $5)
 			 ON CONFLICT (user_id) 
  			DO UPDATE SET 
    			jwt_token    = EXCLUDED.jwt_token,
    			username     = EXCLUDED.username,
    			last_updated = EXCLUDED.last_updated,
       			expire_at    = EXCLUDED.expire_at
  			RETURNING id
			`, [
  				user.id,
  				jwt_token,
  				user.username,
				created_at,
				expire_at
			]);

			console.log('registered : store jwt token : result.rows.id : ' + result.rows[0].id); //Object.keys(result.rows));
		
		}catch(error){
			console.error('registered : store jwt token : failure : ' + error);
		}
	}

	/*
       // Save refresh token to database for a user
	async function saveRefreshToken(user, refresh_token) {
		// Assuming you have a database table for refresh tokens associated with users
		// Save the refresh token with an expiration time (e.g., 1 day)
		
		console.log('registered : saveRefreshToken : store refresh token');
		
		try{
			
   			const result = await pool.query('INSERT INTO refresh_tokens (user_id, refresh_token, username, ) VALUES ($1, $2, $3) RETURNING id', [
				user.id,
				jwt_token,
				user.username	
			]);
			

			// Parse the number from the 'REFRESH_EXPIRY' string and  Extract the number part
			const expiryDays = parseInt(REFRESH_EXPIRY.replace('d', ''), 10); // Extract the number part
			const expires_at = new Date(Date.now() + expiryDays * 24 * 60 * 60 * 1000);

			const result = await pool.query(`
  			INSERT INTO refresh_tokens (user_id, refresh_token, username, created_at, expires_at)
  			VALUES ($1, $2, $3, now(), $4)
 			 ON CONFLICT (user_id) 
  			DO UPDATE SET 
    			refresh_token = EXCLUDED.jwt_token,
    			username      = EXCLUDED.username,
    			last_updated  = now()
  			RETURNING id
			`, [
  				user.id,
  				refresh_token,
  				user.username,
				expires_at
			]);

			console.log('registered : store refresh token : result.rows.id : ' + result.rows[0].id); //Object.keys(result.rows));
		
		}catch(error){
			console.error('registered : store refresh token : failure : ' + error);
		}
	}
        */

	// Function to generate a random refresh token
	function generateRefreshToken() {
		// Create a random string of 64 characters
		const refreshToken = crypto.randomBytes(64).toString('hex');

		/*
		// If expires_at is not provided, calculate it based on default expiry days
                if (!expires_at) {
                    	const expiryDays = parseInt(process.env.REFRESH_EXPIRY?.replace('d', '') || 30); // Default to 30 days
        		expires_at = new Date(Date.now() + expiryDays * 24 * 60 * 60 * 1000).toISOString();
    		}
		*/
		
    	return refreshToken;
}

	// Save refresh token to database for a user
	async function storeRefreshTokenInDatabase(user, refreshToken, created_at, expires_at) {
		// Assuming you have a database table for refresh tokens associated with users
		
		console.log('storeRefreshTokenInDatabase start : user : ', user, ' refreshToken : ', refreshToken, ' created_at : ', created_at, ' expires_at : ', expires_at);
		
		/*
		// Parse the number from the 'REFRESH_EXPIRY' string and  Extract the number part
		const expiryDays = parseInt(REFRESH_EXPIRY.replace('d', ''), 10); // Extract the number part
		
		console.log('storeRefreshTokenInDatabase date : ', new Date(Date.now() + expiryDays * 24 * 60 * 60 * 1000));
		*/
		
		try{
			/*
			await pool.query('INSERT INTO refresh_tokens (user_id, refresh_token, expires_at) VALUES ($1, $2, $3)', [
				user.id,
				refreshToken,
				new Date(Date.now() + expiryDays * 24 * 60 * 60 * 1000) // expiryDays days in the future
			]);
			*/
			
			/*
			// Parse the number from the 'REFRESH_EXPIRY' string and  Extract the number part
			const expiryDays = parseInt(REFRESH_EXPIRY.replace('d', ''), 10); // Extract the number part
			const expires_at = new Date(Date.now() + expiryDays * 24 * 60 * 60 * 1000);
			*/
			
			const result = await pool.query(`
  			INSERT INTO refresh_tokens (user_id, refresh_token, created_at, expires_at)
  			VALUES ($1, $2, $3, $4)
 			 ON CONFLICT (user_id) 
  			DO UPDATE SET 
    			refresh_token = EXCLUDED.refresh_token,
       			created_at    = EXCLUDED.created_at,
       			expires_at    = EXCLUDED.expires_at
  			RETURNING id
			`, [
  				user.id,
  				refreshToken,
				created_at,
				expires_at
			]);
			
		}catch(error){
		console.error('registered : store refresh token : failure : ' + error);
	}
}

/*
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
*/
	
// Get user ID knowing his device Id or android Id
exports.getUserId = async (req, res) => {
try{
  //const androidId = req.params.androidId;
  const androidId = req.query.androidId	
  //console.log('getAndroidId : req : ', req);	
  //console.log('getAndroidId : req.params : ', req.params);	
  console.log('getUserId : androidId : ', androidId);

  //if(true)throw new Error('unexpected issue');
  const user_id = await getUserId_(androidId)
  if(user_id == null){
	console.warn('User not found for androidId:', androidId);
        return res.status(404).json({ message: 'User not found' });
  }
  console.log('getUserId : user_id : ', user_id);
  res.status(200).json({
  	message: 'user id found',
	userId: user_id
  });  
}catch (error) {
    console.error('Error retrieving user ID:', error.message);
    return res.status(500).json({ message: 'Internal server error' });
  }
}

//get id knowing androidId
async function getUserId_(androidId){
	//const username = 'Name147';
	 try {
	    const result = await pool.query('SELECT * FROM users_notification WHERE android_id = $1', [androidId]);
	
	    if (result.rowCount === 0) {
	      //return res.status(404).json({ message: 'android id not found' });
	      return null;  // Explicitly indicate no result
	    }
	    console.log('getUserId : user_id : ', result.rows[0].id);
	    return result.rows[0];
	    
	} catch (error) {
	    console.error('Error querying user ID:', error.message, { androidId, username });
    	    throw new Error('Database query failed'); // Throw an error for unexpected issues
  
  	}	  	  
}

//get id knowing username
async function getUserId__(username){
	//const username = 'Name147';
	 try {
	    const result = await pool.query('SELECT id FROM users_notification WHERE username = $1', [username]);
	
	    if (result.rowCount === 0) {
	      //return res.status(404).json({ message: 'user id not found' });
	      console.log('getUserId__ : user id : user id not found');    
	      return null; 
	    }
	    console.log('getUserId__ : user id : ', result.rows[0].id);
	    return result.rows[0].id;
	    
	} catch (error) {
	    console.error('getUserId__ : Error querying user ID:', error.message, { username });
    	    throw new Error('Database query failed'); // Throw an error for unexpected issues
  	}	  	  
}

	
//get stored shared prefrences of a device Id
exports.getStoredSharedPreferences = async (req, res) => {
  try{
	  //const androidId = req.params.android_id;
	  const androidId = req.query.android_id	
	  //console.log('getStoredSharedPreferences : req : ', req);
	  console.log('getStoredSharedPreferences : req.query : ', req.query);
	  //console.log('getStoredSharedPreferences : req.params : ', req.params);	
	  console.log('getStoredSharedPreferences : androidId : ', androidId);
	
	  //1st step, get the user Id and 'is_session_closed'
	   const user = await getUserId_(androidId); //user ---> result.rows[0]
	  if(user == null){
		console.error('getStoredSharedPreferences : error : user id not found');
		return res.status(200).json({ message: 'user id not found',  isRegistered:false,});
	  }
	  
	  console.log('getStoredSharedPreferences : user : ', user);
	   
	  const user_id           = user.id;
	  const failed_attempts   = user.failed_attempts;
          const lockout_until     = user.lockout_until;
	  const is_session_closed = user.is_session_closed; 
	   
	  console.log('getStoredSharedPreferences : user_id : ', user_id, ' failed_attempts : ', failed_attempts, ' lockout_until : ', lockout_until, ' is_session_closed : ', is_session_closed);
   
	  //2nd step, get stored jwt for this user
	    const jwt_token = await pool.query('SELECT jwt_token FROM jwt_tokens WHERE user_id = $1', [user_id]); 
	    if (jwt_token.rowCount === 0) {
	           console.log('getStoredSharedPreferences :  jwt_token : jwt_token not found');   
		   return res.status(404).json({ message: 'jwt_token not found' });
	    }

	   //here the jwt is found
	   console.log('getStoredSharedPreferences : jwt_token : ', jwt_token.rows[0].jwt_token);
		  
	    //3rd step, get refresh token
	    const refresh_token_ = await pool.query('SELECT refresh_token, expires_at FROM refresh_tokens WHERE user_id = $1', [user_id]); 
	    if (refresh_token_.rowCount === 0) {
	           console.log('getStoredSharedPreferences :  refresh_token_ : refresh_token_ not found');   
		   return res.status(404).json({ message: 'refresh_token_ not found' });
	    }
	    //here the 'refresh_token_' is found.
	    const refresh_token  = refresh_token_.rows[0].refresh_token;
	    const refresh_expiry = refresh_token_.rows[0].expires_at;  
		  
	    console.log('getStoredSharedPreferences : refresh_token : ',  refresh_token);
	     
	    console.log('getStoredSharedPreferences : refresh_expiry : ', refresh_expiry); 
	  
	    //4th step, get sha256 pin
	    const sha256_pin = await pool.query('SELECT sha256_pin FROM pins WHERE user_id = $1', [user_id]); 
	
	    if (sha256_pin.rowCount === 0) {
	           console.log('getStoredSharedPreferences :  sha256_pin : user id : sha256_pin not found');   
		   return res.status(404).json({ message: 'sha256_pin not found' });
	    }
	    
	    //here the 	sha256_pin is found.
	    console.log('getStoredSharedPreferences : sha256_pin : ', sha256_pin.rows[0].sha256_pin);
	
	    //5th step, get fcm token
	    const fcm_token = await pool.query('SELECT fcm_token FROM fcm_tokens WHERE user_id = $1', [user_id]); 
	    if (fcm_token.rowCount === 0) {
	           console.log('getStoredSharedPreferences :  fcm_token : fcm_token not found');   
		   return res.status(404).json({ message: 'fcm_token not found' });
	    }
	    //here the fcm_token is found
	    console.log('getStoredSharedPreferences : fcm_token : ', fcm_token.rows[0].fcm_token);

          //6th step : Retrieve the session id from the database
	  //console.log('getStoredSharedPreferences : 6th step : user_id : ', user_id);
          const sessionQuery = `SELECT * FROM password_change_sessions WHERE user_id = $1`;
          const sessionResult = await pool.query(sessionQuery, [user_id]);
	  let sessionId;
	  if(sessionResult.rowCount > 0){
	    sessionId = sessionResult.rows[0].session_id;
	    console.log('getStoredSharedPreferences : 6th step : sessionId : ', sessionId);  
	  }else{
	    sessionId = null;
	  }
	   console.log('getStoredSharedPreferences : sessionId : ', sessionId);
	  
	    res.status(200).json({
	  	isRegistered:true,
		jwtToken: jwt_token.rows[0].jwt_token, 
	  	refreshToken: refresh_token_.rows[0].refresh_token, 
	  	refreshExpiry: refresh_token_.rows[0].expires_at, 
		sha256Pin:  sha256_pin.rows[0].sha256_pin,
		fcmToken:  fcm_token.rows[0].fcm_token,
	        failedAttempts: failed_attempts,
                lockoutUntil: lockout_until,
		isSessionClosed: is_session_closed,
		sessionId:sessionId 
	});  
  } catch (error) {
    console.error('getStoredSharedPreferences : error : ', error);
    res.status(500).json({ message: 'Error retrieving android id' });
  }
};

exports.setLockoutStatus = async (req, res) => {
    //const username = 'Name147';
    //console.log('Headers:', req.headers);                  // Inspect headers
    console.log('setLockoutStatus : Body:', req.body);       // Inspect body
	
    const {androidId, failedAttempts, lockoutUntil } = req.body;
	
    const lockoutUntilLong = parseInt(lockoutUntil, 10);
     
    const lockoutUntilStamp = (lockoutUntilLong == 0)? null : new Date(lockoutUntilLong);
    
    console.log('setLockoutStatus : lockoutUntilStamp :', lockoutUntilStamp);
	
    try {
        const result = await pool.query(
            `UPDATE users_notification 
             SET failed_attempts = $1, lockout_until = $2 
             WHERE android_id = $3`, 
            [failedAttempts, lockoutUntilStamp, androidId]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.status(200).json({ message: 'Lockout set successfully' });
    } catch (error) {
        console.error('Error setting lockout:', error);
        res.status(500).json({ message: 'Server error' });
    }
};


exports.resetLockoutStatus = async (req, res) => {
    //const username = 'Name147';
    //console.log('resetLockoutStatus : req:', req); 
    //console.log('resetLockoutStatus : Headers:', req.headers); // Inspect headers
    console.log('resetLockoutStatus : Body:', req.body);       // Inspect body
     const { androidId } = req.body;
    console.log('resetLockoutStatus : androidId:', androidId)
    try {
        const result = await pool.query(
            `UPDATE users_notification 
             SET failed_attempts = 0, lockout_until = NULL 
             WHERE android_id = $1`, 
            [androidId]
        );
        //console.log('resetLockoutStatus : result:', JSON.stringify(result));
	    
        if (result.rowCount === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.status(200).json({ message: 'Lockout reset successfully' });
    } catch (error) {
        console.error('Error resetting lockout:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

//set session status
exports.setSessionStatus = async (req, res) => {
    //const username = 'Name147';
    //console.log('resetLockoutStatus : req:', req); 
    //console.log('resetLockoutStatus : Headers:', req.headers); // Inspect headers
    console.log('setSessionStatus : Body:', req.body);           
    const {sessionStatus, androidId } = req.body;

    console.log('setSessionStatus : sessionStatus:', sessionStatus);  
	
    //'sessionStatus' in the body is a string. Convert it to boolean
    //const boolString = "false"; 
    const sessionStatusBoolean = (sessionStatus === 'true'); 

    console.log('setSessionStatus : androidId:', androidId, ' sessionStatus : ', sessionStatusBoolean)
    try {
        const result = await pool.query(
            `UPDATE users_notification 
             SET is_session_closed = $1 
             WHERE android_id = $2`, 
            [sessionStatusBoolean, androidId]
        );
        //console.log('setSessionStatus : result:', JSON.stringify(result));
	    
        if (result.rowCount === 0) {
	    console.log('setSessionStatus : session Status of User not updated');
            return res.status(404).json({ message: 'setSessionStatus : Session Status of User not updated' });
        }
        console.log('setSessionStatus :  SessionStatus updated successfully');
        res.status(200).json({ message: 'setSessionStatus updated successfully' });
    } catch (error) {
        console.error('Error setSessionStatus :', error);
	console.log('setSessionStatus :  SessionStatus server error : ', error );
        res.status(500).json({ message: 'setSessionStatus : Server error'});
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
	console.log('(login : user : ', user);
		    
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

	    //handle the creation and storing the JWT and REFRESH token.
	const{jwt_token, refresh_token, refresh_expires_at} = await handleTokens(user);

	/*
	//current date
	const now = Date.now();

	//created at
	const created_at = new Date(now);

	//JWT expiration date
	const expiryDays = parseInt(JWT_EXPIRY.replace('d', ''), 10); // The radix '10' specifies the base for parsing.
	console.log('register : JWT expiryDays : ', expiryDays); 
	    
	const jwt_expires_at = new Date(now + expiryDays * 24 * 60 * 60 * 1000);
	console.log('register : jwt_expires_at : ', jwt_expires_at);

	//REFRESH expiration date
	const expiryDays_ = parseInt(REFRESH_EXPIRY.replace('d', ''), 10); // The radix '10' specifies the base for parsing.
	console.log('register : REFRESH expiryDays : ', expiryDays_); 
	    
	const refresh_expires_at = new Date(now + expiryDays_ * 24 * 60 * 60 * 1000);
	console.log('register : refresh_expires_at : ', refresh_expires_at);
	    
	// Generate a JWT for the registered user
	const jwt_token = jwt.sign(
		{ userId: user.id, username: user.username }, 	// Payload
		JWT_SECRET, 					// Secret key
		{ expiresIn: JWT_EXPIRY } 			// Token expiry
	);
		
	//save jwt Token in database
	const save_jwt_token = await saveJWTToken(user, jwt_token, created_at, jwt_expires_at);
	
	console.log('registered : jwt_token : ', jwt_token, ' created_at : ', created_at, ' expires_at : ', jwt_expires_at);
	    
	// Generate Refresh token
	const refresh_token = await generateRefreshToken();
	console.log('registered : refresh_token : ', refresh_token, ' refresh_created_at : ', created_at, ' refresh_expires_at : ', refresh_expires_at);
	*/
	/*
	const refresh_expiryDays = parseInt(REFRESH_EXPIRY.replace('d', ''), 10); // '10' is the base parsing
	console.log('registered : refresh_expiryDays : ', refresh_expiryDays);
	
	const refresh_expires_at = new Date(Date.now() + refresh_expiryDays * 24 * 60 * 60 * 1000);
	
	console.log('registered before call : refresh_expires_at : ', refresh_expires_at);
	*/
	    
	//save refresh Token in database
	//const save_refresh_token = await storeRefreshTokenInDatabase(user, refresh_token, created_at, refresh_expires_at);
	  /*  
       console.log('registered : user : ', user, ' refresh_token : ', refresh_token, ' expires_at : ', refresh_expires_at);
	    
	// Send back the 'jwt token' and 'refresh' token along with a success message
	res.status(200).json({ 
		message: 'User registered successfully', 
		jwt_token: jwt_token,
		refresh_token: refresh_token,
		refresh_expiry: refresh_expires_at
	});
	
	console.error('registered successfully');
	*/
	/*
        // Generate JWT tokens and refresh tokens.
        const jwt_token = jwt.sign({ userId: user.id }, JWT_SECRET , { expiresIn: JWT_EXPIRY });
        
		//Generate a random refresh token
		//const refreshToken = jwt.sign({ userId: user.id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });
		
		// Generate Refresh token and store it in db
		const refresh_token = await handleRefreshTokenGeneration(user);
		console.log('login : refresh_token : ' + refresh_token);


        // Optionally store the refresh token in the database or send it to the client
        //await pool.query('INSERT INTO refresh_tokens (user_id, refresh_token) VALUES ($1, $2)', [user.id, refreshToken]);
	*/
	    
        // Send jwt token and refresh token to the client
        //res.status(200).json({ jwt_token:jwt_token, refresh_token:refresh_token, refresh_expires_at: refresh_expires_a});
	res.status(200).json({ 
		message: 'User logged successfully', 
		jwt_token: jwt_token,
		refresh_token: refresh_token,
		refresh_expiry: refresh_expires_at
	});
	    
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
};

async function handleTokens (user){
	//current date
	const now = Date.now();

	//created at
	const created_at = new Date(now);

	//JWT expiration date
	const expiryDays = parseInt(JWT_EXPIRY.replace('d', ''), 10); // The radix '10' specifies the base for parsing.
	console.log('register : JWT expiryDays : ', expiryDays); 
	    
	const jwt_expires_at = new Date(now + expiryDays * 24 * 60 * 60 * 1000);
	console.log('register : jwt_expires_at : ', jwt_expires_at);

	//REFRESH expiration date
	const expiryDays_ = parseInt(REFRESH_EXPIRY.replace('d', ''), 10); // The radix '10' specifies the base for parsing.
	console.log('register : REFRESH expiryDays : ', expiryDays_); 
	    
	const refresh_expires_at = new Date(now + expiryDays_ * 24 * 60 * 60 * 1000);
	console.log('register : refresh_expires_at : ', refresh_expires_at);
	    
	// Generate a JWT for the registered user
	const jwt_token = jwt.sign(
		{ userId: user.id, username: user.username }, 	// Payload
		JWT_SECRET, 					// Secret key
		{ expiresIn: JWT_EXPIRY } 			// Token expiry
	);
		
	//save jwt Token in database
	const save_jwt_token = await saveJWTToken(user, jwt_token, created_at, jwt_expires_at);
	
	console.log('registered : jwt_token : ', jwt_token, ' created_at : ', created_at, ' expires_at : ', jwt_expires_at);
	    
	// Generate Refresh token
	const refresh_token = await generateRefreshToken();
	console.log('registered : refresh_token : ', refresh_token, ' refresh_created_at : ', created_at, ' refresh_expires_at : ', refresh_expires_at);

	/*
	const refresh_expiryDays = parseInt(REFRESH_EXPIRY.replace('d', ''), 10); // '10' is the base parsing
	console.log('registered : refresh_expiryDays : ', refresh_expiryDays);
	
	const refresh_expires_at = new Date(Date.now() + refresh_expiryDays * 24 * 60 * 60 * 1000);
	
	console.log('registered before call : refresh_expires_at : ', refresh_expires_at);
	*/
	    
	//save refresh Token in database
	const save_refresh_token = await storeRefreshTokenInDatabase(user, refresh_token, created_at, refresh_expires_at);
	    
       console.log('registered : user : ', user, ' refresh_token : ', refresh_token, ' expires_at : ', refresh_expires_at);

	return {jwt_token, refresh_token, refresh_expires_at};	    
}

 //called in "login"           
// Generate and store refresh token and store it db
async function handleRefreshTokenGeneration(user) {
	const refreshToken = generateRefreshToken();
	await storeRefreshTokenInDatabase(user, refreshToken);
	return refreshToken;
}



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
