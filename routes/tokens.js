// routes/tokens.js
const express 	           = require('express');
const router  		= express.Router();
const tokensController	= require('../controllers/tokens_controller'); // Point to your controller
const authMiddleware             = require('../middleware/auth');
//const auth_refresh_middleware    = require('../middleware/auth_refresh');

console.log("routes/tokens");

// Define routes
router.post('/refresh-jwt-token', tokensController.refreshJWTToken);                                   // POST /tokens/refresh-jwt-token
router.post('/renew-tokens', authMiddleware, tokensController.renewTokensHandler);                     // POST /tokens/renew-tokens
router.post('/renew-all-tokens', tokensController.renewAllTokensHandler);                              // POST /tokens/renew-all-tokens
router.post('/update-jwt-env', authMiddleware, tokensController.updateJWTEnvironment);                 // POST /tokens/update-jwt_env
router.post('/renew-jwt-update-env', authMiddleware, tokensController.renewTokensUpdateJWTEnvironment);// POST /tokens/renew-jwt-update-env
router.post('/fetch-jwt', tokensController.fetchJWT);                                                  // POST /tokens/fetch-jwt
router.post('/revoke-jwt', tokensController.revokeJWT);                                                // POST /tokens/revoke-jwt
           
//router.get('/:id', usersController.getUser);              // GET /users/:id
//router.put('/:id', usersController.updateUser);           // PUT /users/:id

// Export the router
module.exports = router;
