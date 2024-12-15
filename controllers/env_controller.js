//import renderApi from '@api/render-api';
//const renderApi = require('@api/render-api');

exports.updateEnv = async (req, res) => {

   	console.log('update Env start ');
	
	renderApi.auth('rnd_0zPNWnTmGysVCH6oECy29bMhX6iy');
	renderApi.updateEnvVar({value: 'ccccc'}, {
	  serviceId: 'srv-cseq2m5svqrc73f7ai5g',
	  envVarKey: 'JWT_SECRET'
	})
	  .then(({ data }) => {
		  console.log(data);
		res.status(200).json({ 
				message: 'env variable modified successfully', 
				data:data
			        });
	  })
  	.catch(err => {
		console.error(err);
		res.status(500).send('Internal server error : Error env variable modification');
		}
	);
}

