/*
//const fetch = require('node-fetch');
fetch('http://localhost:5000/send-notification', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
    },
    body: JSON.stringify({
        userId: 'user_id_here', // User ID for whom the notification is intended
        title: 'Notification Title',
        message: 'This is a notification message',
    }),
})
.then(response => response.json())
.then(data => console.log(data))
.catch(error => console.error('Error:', error));
*/
/////////////////////////////////////////////////////////////////////////////////////////////////
/*
const admin      = require('firebase-admin');
const { Pool }   = require('pg'); // PostgreSQL client

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

// Load your Firebase service account key file (you download this from Firebase Console)
const serviceAccount = require('./android-firebase-634a8-firebase-adminsdk-ggw45-6b2ec92cde.json');

// Initialize the Firebase Admin SDK with your service account
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
});

async function getFcmToken(userId) {
  console.log('getFcmToken(userId) :', userId);
  try {
    const result = await pool.query('SELECT device_token FROM fcm_tokens WHERE id = $1', [userId]);
    
    if (result.rows.length > 0) {
      return result.rows[0].device_token; // Assuming 'fcm_token' column contains the FCM token
    } else {
      throw new Error('No FCM token found for this user');
    }
  } catch (error) {
    console.error('Error fetching FCM token from the database:', error);
    throw error;
  }
}

//token: 'dzLsdOIuS6aGkBRx5N_9AB:APA91bF-8qRcPcRAI7BvPugXadfBKJFs29kkuInGcbnKnBuBKG2Tui_ga6_768uWlLb8jApGdExTNR1SC5L7KSn8hTsjXkuXmv7-FAI2aokstIMqi3DyJUzJ9-0ggRiheSteD-AuTdzN',  // Replace with the device FCM token
        

// Function to send the notification
// Function to send FCM notification
async function sendNotification(userId, title, body) {
  try {
    // Retrieve FCM token for the specific user
    const fcmToken = await getFcmToken(userId);
    
	console.log('fcmToken :', fcmToken);
	
    // Define the notification message
    const message = {
      token: fcmToken,
      notification: {
        title: title,
        body: body,
      //data: {
      //  key1: 'value1',
      //  key2: 'value2',
      //}
      }
	};
    // Send the notification
    const response = await admin.messaging().send(message);
    console.log('Notification sent successfully:', response);
  } catch (error) {
    console.error('Error sending notification:', error);
  }
}

// Example usage
sendNotification(2, 'Hello!', 'This is a test notification'); // Replace with actual user ID
*/
/////////////////////////////////////////////////////////////////////////////////////////////////////

const admin      = require('firebase-admin');
const express    = require('express');
const { Pool }   = require('pg'); // PostgreSQL client
const app        = express();
const bodyParser = require('body-parser');

// Set EJS as the template engine
app.set('view engine', 'ejs');

// Middleware to parse form data
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Initialize Firebase Admin SDK
const serviceAccount = require('./android-firebase-634a8-firebase-adminsdk-ggw45-6b2ec92cde.json');
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// PostgreSQL connection setup
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


// Route to get all FCM tokens and render them
app.get('/', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, user_id, device_token FROM fcm_tokens');
    const tokens = result.rows;
	
	//console.log('Sendpoint / : tokens : ', JSON.stringify(tokens));
	
    res.render('index', { tokens });
  } catch (err) {
    console.error('Error retrieving FCM tokens:', err);
    res.status(500).send('Internal server error');
  }
});

// Route to send notifications to all FCM tokens
app.post('/send-to-all', async (req, res) => {
  const message = req.body.message;
  
  try {
    // Fetch all FCM tokens from the database
    const result = await pool.query('SELECT device_token FROM fcm_tokens');
    const tokens = result.rows.map(row => row.device_token); // Extract tokens
	
	console.log('Sending notification token : ', JSON.stringify(tokens));
	
	console.log('/send-to-all : tokens : ', tokens);
    if (tokens.length > 0) {
      // Create a message payload
      const payload = {
        /*
		notification: {
          title: 'Notification from Node.js',
          body: message
        },
		android: {
			priority: 'high',
			notification: {
				icon: 'circle1_xxl',  // Your custom icon (without the file extension)
				//icon: 'gs://android-firebase-634a8.appspot.com/circle1-xxl.png',
				//color: '#ff0000'    // Optional: Custom color for the icon background
			}
		},
		*/
		
        data: {
			title: "Custom Notification",
			body: message, //"This is a custom message",
			//icon: "ic_fcm_notification" // vect icon, working
			icon: "fcm_icon_fresh_transparent_2" // vect icon, working
		}
		//token: '',  // Replace with the device FCM token
      };

		// Send notification to each token
		for (let token of tokens) {
		  console.log(`Sending notification to : ${token}`);
		  const response = await sendFcmNotification(token, payload);
		  
		  console.log(response);
		}

		res.status(200).send('Notification sent to all.');
    } else {
      res.send('No FCM tokens found.');
    }
  } catch (err) {
    console.error('Error sending FCM notification :', err);
    res.status(500).send('Failed to send notifications.');
  }
});

// Function to send FCM notification
	async function sendFcmNotification(fcmToken, payload) {
		console.log('Sending notification : icon : ', payload.data.icon);
		console.log('Sending notification : fcmToken : ', fcmToken);
		try {
			const response = await admin.messaging().send({
			  token: fcmToken,  // Token is specified outside the payload
			  //notification: payload.notification, // Notification is sent as payload
			  data: payload.data  // Data payload (optional)
			  //android: {
				//priority: "high",  // Optional: High priority if needed
			  //}
		});
		console.log('Successfully sent message:', response);
	  } catch (error) {
			console.error('Error sending message :', error);
	  }
	}
	
// Start the server
app.listen(5001, () => {
  console.log('Server is running on port 5001');
});


///////////////////////////////////////////////////////////////////////////////////////////////////


