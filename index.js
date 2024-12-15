
require('dotenv').config();

const express   = require('express');
const http      = require('http');
const socketIo  = require('socket.io');
const pgsql     = require('pgsql');
const fs        = require("fs");
const cors      = require('cors');

// Set up express app and http server
const app 	= express();
//const server 	= http.createServer(app);
//const io 	= socketIo(server);
const { Server } = require("socket.io");
const PORT      = process.env.PORT || 5000

app.use(cors());

//*http
const httpServer = http.createServer(app)
const io         = new Server(httpServer, { /* options */ });
httpServer.listen(PORT, () => console.log(`   Listening on ${ PORT }`));

const jwt        = require('jsonwebtoken');
const bcrypt     = require('bcryptjs');
const crypto     = require('crypto');
const path       = require('path');

// Secret key for signing the token (keep this secret)
//const JWT_SECRET = 'your_jwt_secret_key';
const JWT_SECRET 		= process.env.JWT_SECRET;
const REFRESH_TOKEN_SECRET 	= process.env.REFRESH_TOKEN_SECRET;

console.log("JWT_SECRET : ", JWT_SECRET, " REFRESH_TOKEN_SECRET : ", REFRESH_TOKEN_SECRET);

const CAPTCHA_SITE_KEY = process.env.CAPTCHA_SITE_KEY;
console.log('CAPTCHA_SITE_KEY:', CAPTCHA_SITE_KEY);

// Middleware to parse application/x-www-form-urlencoded data
//The data are sent in FormBody, use : 'app.use(express.urlencoded({ extended: true }))'
//if the data are sent in Json, use : 'app.use(express.json());'
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const REFRESH_EXPIRY = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days in the future
const JWT_EXPIRY     = '1d'; 
//const JWT_EXPIRY   = new Date(Date.now() +  1 * 24 * 60 * 60 * 1000); // 1 days in the future

console.log("REFRESH_EXPIRY = ", REFRESH_EXPIRY, " JWT_EXPIRY = ", JWT_EXPIRY);


// Serve static files from the "public" directory
app.use(express.static('public'));

/*
app
  .get('/', (req, res) => {
	  const options = {
        root: path.join(__dirname)
    };
	console.log('__dirname:', __dirname);
	
	const message = 'Hello World from express listening on ' + PORT;
	const fileName = 'captcha.html';//do not put 'public' branch in front of the name like this : "public/captcha.html"
	//res.send(message);
	
    res.sendFile(fileName, options, function (err) {
        if (err) {
            console.error('Error sending file:', err);
        } else {
            console.log('Sent:', fileName);
        }
    });
  })
  */

//Serve files from the root '/' directory. 'https://..../captcha.html', 'captcha.html' must be in ./captcha.html'
app.get('/', (req, res) => {
    console.log('Serving captcha.html');
    // Path to your captcha.html file
    const filePath = path.join(__dirname, 'public', 'captcha.html');

    // Read the HTML file
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            return res.status(500).send('Error reading HTML file.');
        }

        // Replace the placeholder with the environment variable
        const updatedHtml = data.replace(/data-sitekey=\s*['"]?CAPTCHA_SITE_KEY['"]?/g,  `data-sitekey="${CAPTCHA_SITE_KEY}"`)
		//const updatedHtml = data.replace(/data-sitekey=\s*['"]?HCAPTCHA_SITEKEY['"]?/g, `data-sitekey="${process.env.HCAPTCHA_SITEKEY}"`);
		//const updatedHtml = data.replace(/data-sitekey=\s*['"]?HCAPTCHA_SITEKEY['"]?/g, `data-sitekey="${process.env.HCAPTCHA_SITEKEY}"` 
		//const updatedHtml = data.replace(/data-sitekey=\s*['"]?HCAPTCHA_SITEKEY['"]?/g, `data-sitekey='${process.env.CAPTCHA_SITE_KEY}'` // Use single quotes in the final HTML
        //);
		// Replacement string
        //);
		//const updatedHtml = data.replace(/data-sitekey=\s*['"]?HCAPTCHA_SITEKEY['"]?/g, `data-sitekey="${process.env.CAPTCHA_SITE_KEY}"`);

        // Send the modified HTML
        res.send(updatedHtml);
    });
});

/*
//serves fcm tokens
app.get('/fcm_tokens', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, user_id, device_token FROM fcm_tokens');
    const tokens = result.rows;
	
    console.log('fcm_tokens / : tokens : ', JSON.stringify(tokens));
	
    res.render('index', { tokens });
  } catch (err) {
    console.error('Error retrieving FCM tokens:', err);
    res.status(500).send('Internal server error');
  }
});
*/

// Import routes
const users_routes  		= require('./routes/users');
const tokens_routes 		= require('./routes/tokens');
const fcm_routes    		= require('./routes/fcm');
const notifications_routes    	= require('./routes/notifications');
const pins_routes    	        = require('./routes/pins');
const env_routes    	        = require('./routes/env');

// Use routes
app.use('/users', users_routes);
app.use('/tokens', tokens_routes);
app.use('/fcm', fcm_routes);
app.use('/notifications', notifications_routes);
app.use('/pins', pins_routes);
app.use('/env_', env_routes);

// Set EJS as the template engine
app.set('view engine', 'ejs');

return;

//endpoint : login
app.post('/login', loginUser);

//send notification
var admin = require("firebase-admin");

var serviceAccount = require("./android-firebase-634a8-firebase-adminsdk-ggw45-6b2ec92cde.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "postgres:5432"
});

//send notification
app.post('/send-notification', async (req, res) => {
    const { userId, title, message } = req.body;

    console.log('send-notification : userId ', userId, ' title : ', title, ' message : ', message);

	/*
    // Fetch the FCM token from the database
    const result = await db.query('SELECT fcm_token FROM users WHERE id = $1', [userId]);
    
    if (result.rows.length === 0) {
        return res.status(404).json({ message: 'User not found' });
    }
    */
	
    //const fcmToken = result.rows[0].fcm_token;
	const fcmToken = "dzLsdOIuS6aGkBRx5N_9AB:APA91bF-8qRcPcRAI7BvPugXadfBKJFs29kkuInGcbnKnBuBKG2Tui_ga6_768uWlLb8jApGdExTNR1SC5L7KSn8hTsjXkuXmv7-FAI2aokstIMqi3DyJUzJ9-0ggRiheSteD-AuTdzN";

    const payload = {
        notification: {
            title: title,
            body: message,
        }
    };

    // Send the notification
    admin.messaging().sendToDevice(fcmToken, payload)
        .then((response) => {
            res.status(200).json({ message: 'Notification sent successfully', response });
			console.log('send-notification : successfully');
        })
        .catch((error) => {
            console.error('Error sending notification:', error);
            res.status(500).json({ message: 'Error sending notification', error });
        });
});


// Middleware to authenticate JWT tokens
function authenticateJWT(req, res, next) {
    
	const authHeader = req.headers.authorization;
    console.log("authenticateJWT : authHeader = ", authHeader);

    if (authHeader) {
        const token = authHeader.split(' ')[1];
		
		// Check if the token exists
        if (!token) {
			console.error("No token provided, return 401 Unauthorized ");
			return res.sendStatus(401);  // No token provided, return 401 Unauthorized
		}

        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err) {
                console.error("JWT verification error : ", err);
				console.error("err.name : ", err.name);
				if (err.name === 'TokenExpiredError') {
					return res.status(401).json({ message : 'Token expired' });
				}
				return res.sendStatus(403); // Forbidden
            }

            req.user = user;
            next();
        });
    } else {
        res.sendStatus(401); // Unauthorized
    }
}

//this function go with endpoint 'app.get('/protected','
const authenticateJWT_ = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (authHeader) {
        const token = authHeader.split(' ')[1];

        jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
            if (err) {
                return res.sendStatus(403); // Forbidden
            }

            req.user = user; // Attach user info to the request
            next();
        });
    } else {
        res.sendStatus(401); // Unauthorized
    }
};

// Example protected route
app.get('/protected', authenticateJWT_, (req, res) => {
    res.status(200).json({ message: 'This is a protected route', user: req.user });
});


// Register user endpoint
app.post('/register', async (req, res) => {
    
    console.log('register\n');
	
	const { username, password, androidId, sector, branch } = req.body;

	console.log('register : username : ', username, ' password : ', password, ' androidId : ', androidId, ' sector : ', sector, ' branch : ', branch);
	
    try {
        // Check if user already exists
        const existingUser = await pool.query('SELECT * FROM users_notification WHERE username = $1', [username]);
        if (existingUser.rows.length > 0) {
            console.log('register : the user already exists');
			return res.status(400).json({ message: 'Username already exists' });
        }

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
			refresh_token: refresh_token
		});
		
		console.error('registered successfully');
		
    } catch (error) {
        console.error('registered failure : ' + error);
        res.status(500).json({ message: 'Server error' });
    }
});

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
		try{
			await pool.query('INSERT INTO refresh_tokens (user_id, refresh_token, expires_at) VALUES ($1, $2, $3)', [
				user.id,
				refreshToken,
				//new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days in the future
				REFRESH_EXPIRY // 30 days in the future
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


// Login endpoint
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Check if the user exists
        const userResult = await pool.query('SELECT * FROM users_notification WHERE username = $1', [username]);

        if (userResult.rows.length === 0) {
            return res.status(400).json({ message: 'Invalid username or password' });
        }

        const user = userResult.rows[0];

        // Compare the password with the hashed password stored in the database
        const isPasswordValid = await bcrypt.compare(password, user.password);

		console.log('isPasswordValid : ', isPasswordValid);
		
        if (!isPasswordValid) {
            return res.status(400).json({ message: 'Invalid username or password' });
        }

        // Generate JWT tokens (access and refresh tokens)
        const accessToken = jwt.sign({ userId: user.id }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: JWT_EXPIRY });
        const refreshToken = jwt.sign({ userId: user.id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });

        // Optionally store the refresh token in the database or send it to the client
        await pool.query('INSERT INTO refresh_tokens (user_id, refresh_token) VALUES ($1, $2)', [user.id, refreshToken]);

        // Send tokens back to the client
        res.status(200).json({ accessToken, refreshToken });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});



// Example protected route
app.get('/protected', authenticateJWT, (req, res) => {
    res.status(200).json({ message: 'This is a protected route', user: req.user });
});


//let refreshTokenStore = {};

//logout
app.post('/logout', async (req, res) => {
    const refreshToken = req.body.refreshToken; // Get refresh token from request body

    // Check if the refresh token exists in the database
    const result = await pool.query('DELETE FROM refresh_tokens WHERE refresh_token = $1 RETURNING *', [refreshToken]);

    if (result.rowCount > 0) {
        // Successfully deleted the refresh token
        return res.status(200).json({ message: 'Logout successful' });
    } else {
        // Token not found, invalid token
        return res.status(400).json({ message: 'Invalid refresh token' });
    }
});

//refresh 'jwt token'
//if the expiry date of 'refresh token' is near (3 days) for Example). refresh the 'refresh token'. create a randomly one.
app.post('/refresh-jwt-token', async (req, res) => {
    
	console.log("refresh-jwt-token");
	
	const refreshToken = req.body.refreshToken;
	
	console.log("refresh-jwt-token : refreshToken : ", refreshToken );
	
    // Verify the refresh token
	const {userId, expires_at} = await verifyRefreshToken(refreshToken);
	
	console.log("refresh-jwt-token : refreshToken : userId = ",userId, " expires_at = ", expires_at);
	
	var isRefreshTokenExpired = Date.now() > expires_at;
	
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
    res.json({ new_jwt_token: newJWTToken, new_refresh_token: newRefreshToken});
			
	//update the jwt_tokens table
	if(newJWTToken != null){
		const result = await updateJWTToken(userId, newJWTToken);
	}
});

  // Function to update the new refresh token in the database
  async function updateRefreshToken(userId, newRefreshToken) {
	  
	  console.log('updateRefreshToken : userId = ', userId, " newRefreshToken = ", newRefreshToken);
	  
	  //const expiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days in the future
	  
	  const query = 
		'UPDATE refresh_tokens SET refresh_token = $1, number_update = number_update + 1, expires_at = $2 WHERE user_id = $3';

  try {
		// Execute the query with userId and 'newRefreshToken' as parameters
		await pool.query(query, [newRefreshToken, REFRESH_EXPIRY, userId]);
		
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
		await pool.query(query, [newJWTToken, userId]);
		
		console.log('JWT token updated successfully');
		
		return { success: true };
  } catch (error) {
		console.error('Error updating JWT token:', error);
    return { success: false, error };
  }
}

// API endpoint to retrieve FCM tokens
app.get('/get-fcm-tokens', authenticateJWT, async (req, res) => {
    try {
        // Query to get all fcm_token records from fcm_tokens table
        const result = await pool.query('SELECT user_id, device_token FROM fcm_tokens');
        
        if (result.rows.length > 0) {
            // Return the retrieved fcm tokens
            return res.status(200).json({
                message: 'FCM tokens retrieved successfully',
                tokens: result.rows
            });
        } else {
            return res.status(404).json({
                message: 'No FCM tokens found'
            });
        }
    } catch (error) {
        console.error('Error retrieving FCM tokens:', error);
        return res.status(500).json({
            message: 'Server error while retrieving FCM tokens'
        });
    }
});

	// API endpoint to store FCM token (secure with JWT authentication)
	//app.post('/store-fcm-token', authenticateJWT,  async (req, res) => {
	
	//we can also do the above statement which use 'authenticateJWT' to verify the jwt and extract the user.id
	
	app.post('/store-fcm-token', async (req, res) => {
    
		//console.log('store-fcm-token : req.user =', req.user);  // Output JWT user details
		console.log('store-fcm-token : Raw body =', req.body);  // Log the raw request body

		const jwt_token = req.headers.authorization.split(' ')[1]; // Extract JWT token

		const fcmToken  = req.body.fcm_token;  // Extract the FCM token from the request body
		//const userId    = req.user.userId;
		
		const decodedToken 	= await verifyJwtToken(jwt_token);  // Verify the JWT token
		const userId 		= decodedToken.userId;
		
		if (!fcmToken) {
			return res.status(400).json({ message: 'FCM token is required' });  // Handle missing token
		}

		// Call the function to store the token in the PostgreSQL database
		const result = await storeFCMToken(userId, fcmToken);

		if (result.success) {
			res.status(200).json({ message: 'FCM token stored successfully' });
			console.log('store-fcm-token : FCM token stored successfully');  

		} else {
			res.status(500).json({ message: 'Failed to store FCM token' });
			console.log('store-fcm-token : Failed to store FCM token'); 
			
		}
		
    
    //console.log('FCM Token received:', fcmToken);

    // Send success response
    //res.status(200).json({ message: 'FCM token stored successfully' });
});


function verifyJwtToken(jwtToken) {
    return new Promise((resolve, reject) => {
        // Verify the jwt token using the secret key
        jwt.verify(jwtToken, JWT_SECRET, (err, decoded) => {
            if (err) {
                // If there's an error (e.g., token expired, invalid), reject the promise
                return reject(err);
            }

            // If token is valid, resolve the promise with the decoded payload
            resolve(decoded);
        });
    });
}


// Function to store or update the FCM token in the database
  async function storeFCMToken(userId, fcmToken) {
	  
	  console.log('storeFCMToken : userId = ', userId, " fcmToken = ", fcmToken);
	  
	  const query = `
		INSERT INTO fcm_tokens (user_id, device_token, last_updated)
		VALUES ($1, $2, CURRENT_TIMESTAMP)
		ON CONFLICT (user_id)
		DO UPDATE SET device_token = EXCLUDED.device_token, last_updated = CURRENT_TIMESTAMP;
	  `;

  try {
		// Execute the query with userId and fcmToken as parameters
		await pool.query(query, [userId, fcmToken]);
		
		console.log('FCM token stored successfully');
		
		return { success: true };
  } catch (error) {
		console.error('Error storing FCM token:', error);
    return { success: false, error };
  }
}

/*
app.post('/store-fcm-token', (req, res) => {
    const { fcmToken } = req.body;
	
	console.log("store-fcm-token : req.body = ", req.body, " fcmToken = ", fcmToken);
    
	// Here, you can store the FCM token in your database
    console.log("Received FCM token:", fcmToken);

    // Respond to the client
    res.json({ message: 'FCM token received successfully' });
});
*/

// Function to authenticate the user and generate a token
async function loginUser(req, res) {
	console.log("loginUser : req.body = ", req.body);
	
    const { username, password } = req.body;
	console.log("loginUser : username = ", username, " password = ", password);

	/*
    // Find user in the database
    const user = users.find(u => u.username === username);
    if (!user) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Check if the password is correct
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }
	*/
	
    // Generate JWT token (expiry can be set as required)
    //const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
	const token = jwt.sign({ userId: '99'}, JWT_SECRET, { expiresIn: JWT_EXPIRY });

    res.json({ token });
}

//https
//const httpsServer = https.createServer(httpOptions, app);
//const io          = new Server(httpsServer, { /* options */ });
//httpsServer.listen(PORT, () => console.log(`   Listening on ${ PORT }`));


//const url      = require('url');
//const utf8     = require('utf8');
//const crypto   = require('crypto');
//const route      = require('./routes') // an 'index.js' is expected in folder 'routes'

//module.exports = io;

///const mysql = require('mysql2')
//console.log('process.env.DATABASE_URL = ' + process.env.DATABASE_URL)
//const connection = mysql.createConnection(process.env.DATABASE_URL)
//console.log('Connected to PlanetScale!')
//connection.end();

//Sequelize-pgsql
//io.use(sequelize('pgsql', 'postgres', 'tomcat14200', { host: 'localhost' }, 'D:\node-pg-sequelize\models'));

const { Pool } = require('pg');

/*
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});
*/

//const Pool = require('pg').Pool

// dont forget 'D:\Postgresql15\data\pg_hba.conf'. move the entry 'all all 127.0.0.1/32' to the first place
//localhost
const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'postgres',
  password: 'tomcat@14200',
  port: 5432,
  client_encoding: 'utf8',
  //ssl: true,
  max: 20,
  min: 1,
  idleTimeoutMillis: 1000,
})


/*
//'192.168.43.57' dont forget to ad 'host    all        all        192.168.43.57/32 	    scram-sha-256' in 'D:\Postgresql15\data\pg_hba.conf'
// this entry must be the unique entry in 'IPv4 local connections' or preceed 'all all 127.0.0.1/32'
const pool = new Pool({
  user: 'postgres',
  host: '192.168.43.57',
  database: 'postgres',
  password: 'tomcat@14200',
  port: 5432,
  client_encoding: 'utf8',
  //ssl: true,
  max: 20,
  min: 1,
  idleTimeoutMillis: 1000,
})
*/

/*
//Heroku
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});
*/

/*
//Heroku other color db qui marche au 21-05-22
const pool = new Pool({
  connectionString: process.env.HEROKU_POSTGRESQL_PURPLE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});
*/

/*
//Render
const pool = new Pool({
  //connectionString: DATABASE_URL,
   connectionString:process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});
*/

/*
//HelioHost
const pool = new Pool({
  user: 'tomcaty_tomatish',
  host: 'johnny.heliohost.org',
  database: 'tomcaty_Supabase_pgsql',
  password: 'tomcat14200',
  port: 5432,
  client_encoding: 'utf8',
  //ssl: true,
  max: 20,
  min: 1,
  idleTimeoutMillis: 1000,
})
*/

/*
//Render + Aiven + env
const pool = new Pool({
  user: process.env.USER,
  host: process.env.HOST,
  database: process.env.DATABASE,
  password: process.env.PASSWORD,
  port: process.env.PORT,
  client_encoding: 'utf8',
  ssl: {
    rejectUnauthorized: true,
    ca: fs.readFileSync("./ca.pem").toString(),
  },
  max: 20,
  min: 1,
  idleTimeoutMillis: 1000,
});
*/

/*
//Render + Heliohost + env
const pool = new Pool({
  user: process.env.USER1,
  host: process.env.HOST1,
  database: process.env.DATABASE1,
  password: process.env.PASSWORD1,
  port: process.env.PORT1,
  client_encoding: 'utf8',
  max: 20,
  min: 1,
  idleTimeoutMillis: 1000,
});
*/

//console.log('process.env.DATABASE_URL = ' + process.env.DATABASE_URL);
console.log('pool = ' + pool);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
//Testing db
//////////////////////////////////////////////////////////////////////////////////////////////////////////////

var query = "SELECT COUNT(device_token) FROM fcm_tokens";
pool.query(query,[], async(error, results) =>{
		
			const promise = new Promise((resolve, reject) => {
				 resolve(results); 
			});
			
			//if(error)(reject("promise error "+error)); 
			let res = await promise;
			promise.then((value) => {	// value et result la même chose
			  console.log("///////////////// promise then 'SELECT COUNT(device_token) FROM fcm_tokens'  results = " + results + " count = " + results.rows[0].count); //JSON.stringify(results.rowCount));
				
			  var res = (results.rowCount == 1) ? "success" : "failure" ;
			  console.log("/////////////// Testing db : status = " + res);
			  
			}).catch((error) =>{
				console.log("promise 'SELECT COUNT(device_token) FROM fcm_tokens' error : " + error.message);
				console.log("promise 'SELECT COUNT(device_token) FROM fcm_tokens' error : " + error.stack);
				console.error(error);
			});
		});
		
//////////////////////// end testing db /////////////////////////////////////////////////////////////////////////

// Listen for incoming socket connections
io.on('connection', (socket) => {
    console.log('New client connected');

   //test
	socket.on('chat_message', (msg) => {
		console.log("chat message, msg = " + msg);
	});

    // Listen for the 'storeToken' event from the client
    socket.on('storeToken', (data) => {
        console.log('Token received:', data.token);

        // Store token in the database
        const query = `INSERT INTO fcm_tokens (user_id, device_token)
                       VALUES (?, ?)
                       ON DUPLICATE KEY UPDATE device_token = ?, last_updated = CURRENT_TIMESTAMP`;

        connection.query(query, [data.userId, data.token, data.token], (err, result) => {
            if (err) {
                console.error('Error saving token:', err);
                return;
            }

            // Send acknowledgment to the client
            socket.emit('tokenStored', { message: 'Token stored successfully' });
        });
    });//end socket.on('storeToken

    // Handle client disconnect
    socket.on('disconnect', () => {
        console.log('Client disconnected');
    });
});//io.on('connection'


