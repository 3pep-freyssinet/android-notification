// routes/environment.js
const express 			= require('express');
const router  			= express.Router();
const envController	= require('../controllers/env_controller'); // Point to your controller
const authMiddleware = require('../middleware/auth');

console.log('routes : environment');

// Define routes
router.put('/update-env', envController.updateEnv);   // PUT /update_env/update-env
