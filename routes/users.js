// routes/users.js
const express         = require('express');
const router          = express.Router();

const usersController           = require('../controllers/users_controller'); // Point to your controller
const authMiddleware            = require('../middleware/auth');
const resolveUserIdMiddleware   = require('../middleware/resolveUserIdMiddleware');


console.log(' routes users ');

// Define routes
router.post('/register',          usersController.registerUser);                     // POST /users/register
router.post('/login',             authMiddleware, usersController.loginUser);        // POST /users/login
router.post('/verify-user',       usersController.verifyUser);                       // POST /users/verify-user
//router.post('/suggest-user',    usersController.suggestUser);                      // POST /users/suggest-user
router.post('/user-profile',      usersController.createUserProfile);                // POST /users/user-profile
router.post('/update-user-profile', authMiddleware, usersController.updateUserProfile); // POST /users/update-user-profile
router.post('/check-user-profile',   usersController.checkUserProfile);              // POST /users/check-user-profile
router.get('/get-email',          authMiddleware, usersController.getUserEmail);     // GET /users/get-email?username=

router.post('/change-password',   authMiddleware, usersController.changePassword);   // POST /users/change-password
router.post('/check-credentials', authMiddleware, usersController.checkCredentials); // POST /users/check-credentials
router.post('/match-password',    authMiddleware, usersController.matchPassword);    // POST /users/match-password
router.post('/update-password',   authMiddleware, usersController.updatePassword);   // POST /users/update-password
router.post('/forgot-password',   usersController.forgotPassword);                   // POST /users/forgot-password
router.post('/reset-password',    usersController.resetPassword);                    // POST /users/reset-password
router.post('/verify-reset-token',    usersController.verifyResetToken);             // POST /users/verify-reset-token
router.post('/remove-ban',        authMiddleware, usersController.removeBan);        // POST /users/remove-ban

router.delete('/delete-resset-password-token',    usersController.deleteRessetPasswordToken);   // POST /users/delete-resset-password-token

router.post('/lookup-by-id', usersController.lookupById);                      // POST /users/lookup-by-id
router.get('/user_id',                                usersController.getUserId);                     // GET /users/user_id?user_id=
router.get('/get-stored-shared-preferences',          usersController.getStoredSharedPreferences);    // GET /users/get-stored-shared-preferences?android-id=
router.post('/set-lockout-status', authMiddleware,    usersController.setLockoutStatus);              // POST /users/set-lockout-status
router.post('/reset-lockout-status',  authMiddleware, usersController.resetLockoutStatus);            // POST /users/reset-lockout-status

router.post('/set-session-status',  authMiddleware,   usersController.setSessionStatus);              // POST /users/set-session-status
router.post('/get-session-status',  usersController.getSessionStatus);                                // POST /users/get-session-status
router.post('/close-session',       authMiddleware,   usersController.closeSession);                  // POST /users/close-session

router.get('/get-change-password-session-progress',   authMiddleware,   usersController.getChangePasswordSessionProgress);  // GET /users/get-change-password-session-progress
router.get('/check-change-password-session',          authMiddleware,   usersController.checkChangePasswordSession);        // GET /users/check-change-password-session

router.delete('/clear-change-password-session',       authMiddleware,   usersController.clearChangePasswordSession);        // DELETE /users/clear-change-password-session

router.patch('/update-firebase-id', authMiddleware, resolveUserIdMiddleware, usersController.updateFirebaseId);             // PATCH /users/update-firebase-id

//router.get('/:id', 		   usersController.getUser);                         // GET /users/:id
//router.put('/:id', 		   usersController.updateUser);                      // PUT /users/:id

router.post('/verify-captcha', usersController.verifyCaptcha);               // POST /users/verify-captcha

router.post('/send-email', authMiddleware, usersController.sendEmail);       // POST /users/send-email


// Export the router
module.exports = router;
