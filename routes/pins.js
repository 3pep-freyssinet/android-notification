
// routes/pins.js
const express 			= require('express');
const router  			= express.Router();
const pinsController	= require('../controllers/pins_controller'); // Point to your controller
//const authMiddleware = require('../middleware/auth');

console.log('routes : pins');

// Define routes
router.post('/get-pins', pinsController.postGetPins);   // POST /pins/get-pins

//router.get('/get-all-fcm-tokens',   fcmController.getAllFCMTokens);    // GET /fcm/get-all-fcm-tokens
//router.post('/store-fcm-tokens',    fcmController.storeFCMTokens);     // POST /fcm/store-fcm-tokens
//router.post('/store-fcm-token', authMiddleware, fcmController.storeFCMToken);  // POST /fcm/store-fcm-tokens


//router.get('/:id', usersController.getUser);                   // GET /users/:id
//router.put('/:id', usersController.updateUser);                // PUT /users/:id

// Export the router
module.exports = router;
