
// routes/fcm.js
const express 			          = require('express');
const router  			          = express.Router();
const notificationController	= require('../controllers/notifications_controller'); 

console.log('notifications routes');

// Define routes
router.post('/send-to-all', notificationController.send-to-all);   // POST /notifications/send-to-all

// Export the router
module.exports = router;
