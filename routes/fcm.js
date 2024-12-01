// routes/fcm.js
const express 			= require('express');
const router  			= express.Router();
const fcmController	= require('../controllers/fcm_tokens_controller'); // Point to your controller
const authMiddleware = require('../middleware/auth');

console.log('routes');

// Define routes
router.post('/post-all-fcm-tokens', fcmController.postAllFCMTokens);   // POST /fcm/post-all-fcm-tokens
router.get('/get-all-fcm-tokens',   fcmController.getAllFCMTokens);    // GET /fcm/get-all-fcm-tokens
//router.post('/store-fcm-tokens',    fcmController.storeFCMTokens);     // POST /fcm/store-fcm-tokens
router.post('/store-fcm-token', authMiddleware, fcmController.storeFCMToken);  // POST /fcm/store-fcm-tokens


//router.get('/:id', usersController.getUser);                   // GET /users/:id
//router.put('/:id', usersController.updateUser);                // PUT /users/:id

// Export the router
module.exports = router;

const authMiddleware = require('../middleware/auth');

// Protect the store FCM token route
router.post('/store-fcm-token', authMiddleware, fcmController.storeFCMToken);  // POST /fcm/store-fcm-tokens
