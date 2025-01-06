// routes/users.js
const express         = require('express');
const router          = express.Router();
const usersController = require('../controllers/users_controller'); // Point to your controller

console.log(' routes users ');

// Define routes
router.post('/register', usersController.registerUser);             // POST /users/register
router.post('/login',    usersController.loginUser);                // POST /users/login

router.get('/user_id',  usersController.getUserId);                // GET /users/user_id?user_id=
router.get('/get_stored_shared_preferences',  usersController.getStoredSharedPreferences);    // GET /users/get_stored_shared_preferences?android_id=
router.get('/get-check-lockout-status', usersController.checkLockoutStatus);         // GET /users/get-check-lockout-status?android-id=

//router.get('/:id', 		   usersController.getUser);                    // GET /users/:id
//router.put('/:id', 		 usersController.updateUser);                 // PUT /users/:id

router.post('/verify-captcha', usersController.verifyCaptcha);      // POST /users/verify-captcha

// Export the router
module.exports = router;
