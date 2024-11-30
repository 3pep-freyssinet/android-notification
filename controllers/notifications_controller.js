require('dotenv').config();
const pool   = require('../db'); // Assuming you use a database pool for Postgres or MySQL
const bcrypt = require('bcryptjs');
const jwt    = require('jsonwebtoken');
const crypto = require('crypto');
const axios  = require('axios');
const http   = require('http');


// post all notifications to all users tokens
exports.postNotificationsToAllUsers = async (req, res) => {

  console.log('Sending notification to all');
  
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
        data: {
			title: "Custom Notification",
			body: message, //"This is a custom message",
			//icon: "ic_fcm_notification" // vect icon, working
			icon: "fcm_icon_fresh_transparent_2" // vect icon, working
		}
	
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
		});
		console.log('Successfully sent message:', response);
	  } catch (error) {
			console.error('Error sending message :', error);
	  }
}
