// routes/tokens.js
const express 			= require('express');
const router  			= express.Router();
const tokensController	= require('../controllers/tokens_controller'); // Point to your controller

// Define routes
router.post('/refresh-jwt-token', tokensController.refreshJWTToken);   // POST /tokens/refresh-jwt-token
router.post('/renew-tokens', tokensController.renewTokens);            // POST /tokens/renew-tokens

//router.get('/:id', usersController.getUser);              // GET /users/:id
//router.put('/:id', usersController.updateUser);           // PUT /users/:id

// Export the router
module.exports = router;
