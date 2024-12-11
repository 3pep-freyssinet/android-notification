
// routes/pins.js
const express 			  = require('express');
const router  			  = express.Router();
const pinsController	= require('../controllers/pins_controller'); // Point to your controller
const authMiddleware  = require('../middleware/auth_pins');

console.log('routes : pins');

// Define routes
router.get('/get-pins', authMiddleware, pinsController.getPins);                           // GET /pins/get-pins
router.get('/get-latest-sha256pin', authMiddleware, pinsController.getLatestSHA256Pin);    // GET /pins/get-latest-sha256pin

             
//used in "cron-job"
router.get('/fetch-certificate', authMiddleware, pinsController.fetchCertificate);                // GET /pins/fetch-certificate
router.post('/store-certificate', authMiddleware, pinsController.storeCertificate);               // POST /pins/store-certificate
router.post('/fetch-store-certificate', authMiddleware, pinsController.fetchStoreCertificate);     // POST /pins/fetch-store-certificate


//router.get('/get-all-fcm-tokens',   fcmController.getAllFCMTokens);    // GET /fcm/get-all-fcm-tokens
//router.post('/store-fcm-tokens',    fcmController.storeFCMTokens);     // POST /fcm/store-fcm-tokens
//router.post('/store-fcm-token',     authMiddleware, fcmController.storeFCMToken);  // POST /fcm/store-fcm-tokens


//router.get('/:id', usersController.getUser);                   // GET /users/:id
//router.put('/:id', usersController.updateUser);                // PUT /users/:id

// Export the router
module.exports = router;
