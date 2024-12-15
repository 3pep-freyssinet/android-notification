// routes/env.js
const express 			= require('express');
const router  			= express.Router();
const updateEnvController	= require('../controllers/update_env_controller'); // Point to your controller
const authMiddleware = require('../middleware/auth');

console.log('routes : env');

// Define routes
router.put('/update-env', updateEnvController.updateEnv);   // PUT /update_env/update-env
