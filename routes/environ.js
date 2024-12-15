
// routes/environment.js
const express 			= require('express');
const router  			= express.Router();

const envController	= require('../controllers/env_controller'); // Point to your controller
//const authMiddleware = require('../middleware/auth');

console.log('routes : environment');

// Define routes
router.put('/update-env', envController.updateEnv);   // PUT /environ/update-env

// Export the router
module.exports = router;

