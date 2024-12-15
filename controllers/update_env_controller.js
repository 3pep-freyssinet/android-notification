
exports.storeFCMToken = async (req, res) => {

   console.log('fcm tokens : store fcm token');
	
   // Extract token and user information
   const { fcm_token } = req.body;
