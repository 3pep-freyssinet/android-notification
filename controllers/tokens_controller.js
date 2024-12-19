require('dotenv').config();
const pool   = require('../db'); // Assuming you use a database pool for Postgres or MySQL
const bcrypt = require('bcryptjs');
const jwt    = require('jsonwebtoken');
const crypto = require('crypto');
const axios  = require('axios');

//used in update environment variables
const RENDER_SERVICE_ID = "srv-cseq2m5svqrc73f7ai5g"; 		//found here : "https://dashboard.render.com/web/srv-cseq2m5svqrc73f7ai5g"
const RENDER_API_KEY    = "rnd_0zPNWnTmGysVCH6oECy29bMhX6iy"; 	//found in settings

const JWT_SECRET 		= process.env.JWT_SECRET;
const REFRESH_TOKEN_SECRET 	= process.env.REFRESH_TOKEN_SECRET;

//const REFRESH_EXPIRY = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days in the future
//const JWT_EXPIRY     = '1d'; 

const JWT_EXPIRY 		= process.env.JWT_EXPIRY;
const REFRESH_EXPIRY 		= process.env.JWT_REFRESH_EXPIRY;

const ALERT_TIME     = 3 * 24 * 60 * 60 * 1000 //3 days, trigger

//console.log('process.env.DATABASE_URL = ' + process.env.DATABASE_URL);
console.log('pool = ' + pool);

// Register a new user
exports.refreshJWTToken = async (req, res) => {
	// refresh JWT Token endpoint
    
    console.log('refresh JWT Token\n');
	
	const refreshToken = req.body.refreshToken;
	
	console.log("refresh-jwt-token : refreshToken : ", refreshToken );
	
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

   // Function to generate a random refresh token
	function generateRefreshToken() {
		// Create a random string of 64 characters
		const refreshToken = crypto.randomBytes(64).toString('hex');
    return refreshToken;
	}
	
   // Function to update the new refresh token in the database
   async function updateRefreshToken(userId, newRefreshToken) {
	  
	  console.log('updateRefreshToken : userId = ', userId, " newRefreshToken = ", newRefreshToken);
	  
	  //const expiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days in the future
	  
	  const query = 
		'UPDATE refresh_tokens SET refresh_token = $1, number_update = number_update + 1, expires_at = $2 WHERE user_id = $3';

  try {
		// Execute the query with userId and 'newRefreshToken' as parameters
	        // Parse the number from the 'REFRESH_EXPIRY' string and extract the number part
		const expiryDays  = parseInt(REFRESH_EXPIRY.replace('d', ''), 10); // Extract the number part
		const expiryDays_ = new Date(Date.now() + expiryDays * 24 * 60 * 60 * 1000);
	  
		console.log('storeRefreshTokenInDatabase date : ', new Date(Date.now() + expiryDays * 24 * 60 * 60 * 1000));
		await pool.query(query, [newRefreshToken, expiryDays_, userId]);
		
		console.log('refresh token updated successfully');
		
		return { success: true };
  } catch (error) {
		console.error('Error updating JWT token:', error);
    return { success: false, error };
  }
}
	

// Verify the refresh token using the secret key. 
//Since this refresh token has been generated randomly, we cannot use 'REFRESH_TOKEN_SECRET'. 
//We will compare the provided refresh token with the stored in db.
async function verifyRefreshToken(refreshToken) {
    /*
	return new Promise((resolve, reject) => {
        jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, (err, user) => {
            if (err) {
                // If there's an error (e.g., token expired, invalid), reject the promise
				console.log("refresh-token : error : ", err );
                return reject(err);
            }

            // If token is valid, resolve the promise with the decoded payload
			console.log("refresh-token : user.userId : ", user.userId );
            resolve(user);
        });
    });
	*/
	
	const result = await pool.query('SELECT * FROM refresh_tokens WHERE refresh_token = $1', [refreshToken]);
    if (result.rows.length === 0) {
        throw new Error('Invalid refresh token');
		console.log('verifyRefreshToken : Invalid refresh token');
    }
    // Token is valid
	console.log('verifyRefreshToken : successful refresh token : user_id : ', result.rows[0].user_id);
	return {userId:result.rows[0].user_id, expires_at:result.rows[0].expires_at};
}

// Function to update the JWT token in the database
  async function updateJWTToken(userId, newJWTToken) {
	  
	  console.log('updateJWTToken : userId = ', userId, " newJWTToken = ", newJWTToken);
	  
	  const query = 
		'UPDATE jwt_tokens SET jwt_token = $1, number_update = number_update + 1 WHERE user_id = $2';

  try {
		// Execute the query with userId and fcmToken as parameters
		const result = await pool.query(query, [newJWTToken, userId]);
		
		console.log('*************************** JWT token updated successfully : result : ', result);
		
		return { success: true };
  } catch (error) {
		console.error('Error updating JWT token:', error);
    return { success: false, error };
  }
}


////////////////////////////////////////////////////////////////////////////////////////////////
// Function to simulate storing tokens, e.g., updating in a database or environment variables
const storeTokens = async (userId, accessToken, refreshToken) => {
    console.log('Storing Tokens...');
    console.log('Access Token:', accessToken);
    console.log('Refresh Token:', refreshToken);
    // Add your logic to persist tokens in a database or environment variables
    
    try {
	    const storeNewJWTToken        = await updateJWTToken(userId, accessToken);
	    const storeNewRefreshJWTToken = await updateRefreshToken(userId, refreshToken);
    }catch (error) {
        console.error('Error during storing jwt or refrech tokens :', error);
        //res.status(500).json({ error: 'Failed to store jwt or refresh tokens' });
    }
};

// Exported function to renew tokens called from cron-job to renew 'jwt' and 'refresh-jwt' tokens and store them in database.
exports.renewTokens = async (req, res) => {
    try {
        console.log('Token renewal process started...');
        //const userId = 'your_user_id'; // Replace with the real user ID or identifier
 	
	// Get the userId from the middleware (req.user is populated in auth.js)
        const userId = req.user.userId;
       console.log('Token renewal : userId ', userId);
	//console.log('Token renewal : req.user ', JSON.stringify(req.user));    
	    
        if (!userId) {
           console.log('Token renewal : User ID is missing in the request ');
	   return res.status(400).json({ error: 'User ID is missing in the request' });
		 
        }
   
        // Generate new Access Token = jwt token
        const accessToken = jwt.sign({ userId }, JWT_SECRET, {
            expiresIn: JWT_EXPIRY || '7d', // Use "7d" as default if not in environment variables
        });

        // Generate new Refresh Token
        const refreshToken = jwt.sign({ userId }, REFRESH_TOKEN_SECRET, {
            expiresIn: REFRESH_EXPIRY || '30d', // Use "30d" as default if not in environment variables
        });

        // Store the tokens (access and refresh) (persist in DB, file, or environment variables)
        await storeTokens(userId, accessToken, refreshToken);

        // Respond with success message
        res.status(200).json({
            message: 'Tokens renewed successfully',
            accessToken,
            refreshToken,
        });
    } catch (error) {
        console.error('Error during token renewal:', error);
        res.status(500).json({ error: 'Failed to renew tokens' });
    }
};

//update jwt environment token
exports.updateJWTEnvironment = async (jwt_token) => {
        /*
	console.log('updateJWTEnvironment : userId :', userId);
	
        if (!userId) {
            return res.status(400).json({ error: 'User ID is missing in the request' });
        } 
	
 try {
    // Connect to PostgreSQL
    //const client = new Client(DATABASE_CONFIG);
    //await client.connect();

    // Fetch JWT from the database
    const result      = await pool.query("SELECT jwt_token FROM jwt_tokens WHERE user_id = $1", [userId]);
    const jwt_token_  = result.rows[0].jwt_token;
	 
    console.log('updateJWTEnvironment : jwt_token :', jwt_token_);    

    if (!jwt_token) {
      //await client.end();
       console.error('updateJWTEnvironment : error :', "No JWT token found in the database.");    
	return;    
      //return res.status(404).send({ error: "No JWT token found in the database." });
    }
    */

try {
    // Update Render environment variable
    const response = await axios.put(
      `https://api.render.com/v1/services/${RENDER_SERVICE_ID}/env-vars/JWT_TOKEN`,
      { value: jwt_token },
      {
        headers: {
          Authorization: `Bearer ${RENDER_API_KEY}`,
          "Content-Type": "application/json",
        },
      }
    );

    console.log("Render environment variable updated:", response.data);
    //await client.end();
	console.log('JWT token environment updated successfully.', response.data); 
    //res.status(200).send({ message: "JWT token environment updated successfully.", data: response.data });
  } catch (error) {
    console.error("Error updating JWT token environment:", error.message);
    //res.status(500).send({ error: error.message });
  }
};


//merge the renew tokens and update environment variables
exports.renewTokensUpdateJWTEnvironment = async (req, res) => {
    console.log('Combined Process: Renew Tokens and Update Environment');
   try {
        
	   
        // Step 1: Renew JWT, refresh tokens and save them in database.
        const newToken = await exports.renewTokens(req, res); // Reuse renewTokens function
	const userId = req.user.userId; // Extract userId from the middleware-authenticated request
        
	console.log(`Step 1 Completed. UserId: ${userId}, NewToken: ${newToken}`);

        // Step 2: Update JWT in environment variable
        const updateResult = await exports.updateJWTEnvironment(newToken);
        
	// Send success response
	 console.log('JWT token renewed and environment variable updated successfully');
        //return res.status(200).json({
        //    message: 'JWT token renewed and environment variable updated successfully.',
        //    newToken: newToken,
        //    updateResult: updateResult,
        //});
    } catch (error) {
        console.error('Error in renewTokensUpdateJWTEnvironment:', error.message);
        //return res.status(500).json({
        //    message: 'Failed to renew token and update environment variable.',
        //    error: error.message,
        //});
    }
};
