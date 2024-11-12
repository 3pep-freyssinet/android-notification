// routes/fcm.js
const express 			= require('express');
const router  			= express.Router();
const fcmController	= require('../controllers/fcm_tokens_controller'); // Point to your controller

// Define routes
router.post('/post-all-fcm-tokens', fcmController.postAllFCMTokens);   // POST /fcm/all-fcm-tokens
router.get('/get-all-fcm-tokens',   fcmController.getAllFCMTokens);    // GET /fcm/all-fcm-tokens

//router.get('/:id', usersController.getUser);                   // GET /users/:id
//router.put('/:id', usersController.updateUser);                // PUT /users/:id

// Export the router
module.exports = router;
