// routes/users.js
const express         = require('express');
const router          = express.Router();
const usersController = require('../controllers/users_controller'); // Point to your controller
const authMiddleware  = require('../middleware/auth');

console.log(' routes users ');

// Define routes
router.post('/register', usersController.registerUser);                              // POST /users/register
router.post('/login',    usersController.loginUser);                                 // POST /users/loginchangePassword
router.post('/change-password',   authMiddleware, usersController.changePassword);   // POST /users/change-password
router.post('/check-credentials', authMiddleware, usersController.checkCredentials); // POST /users/check-credentials
router.post('/match-password',    authMiddleware, usersController.matchPassword);    // POST /users/match-password
router.post('/update-password',   authMiddleware, usersController.updatePassword);   // POST /users/update-password
router.post('/forgot-password',   usersController.forgotPassword);                   // POST /users/forgot-password

router.get('/user_id',                                usersController.getUserId);                     // GET /users/user_id?user_id=
router.get('/get-stored-shared-preferences',          usersController.getStoredSharedPreferences);    // GET /users/get-stored-shared-preferences?android-id=
router.post('/set-lockout-status', authMiddleware,    usersController.setLockoutStatus);              // POST /users/set-lockout-status
router.post('/reset-lockout-status',  authMiddleware, usersController.resetLockoutStatus);            // POST /users/reset-lockout-status
router.post('/set-session-status',  authMiddleware,   usersController.setSessionStatus);              // POST /users/set-session-status
router.get('/get-change-password-session-progress',   authMiddleware,   usersController.getChangePasswordSessionProgress);  // GET /users/get-change-password-session-progress
router.get('/check-change-password-session',          authMiddleware,   usersController.checkChangePasswordSession);        // GET /users/check-change-password-session

router.delete('/clear-change-password-session',       authMiddleware,   usersController.clearChangePasswordSession);        // DELETE /users/clear-change-password-session


//router.get('/:id', 		   usersController.getUser);                 // GET /users/:id
//router.put('/:id', 		   usersController.updateUser);              // PUT /users/:id

router.post('/verify-captcha', usersController.verifyCaptcha);       // POST /users/verify-captcha

// Export the router
module.exports = router;
