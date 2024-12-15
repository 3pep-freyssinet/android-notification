import renderApi from '@api/render-api';

exports.updateEnv = async (req, res) => {

   console.log('update Env start ');
	
renderApi.auth('rnd_0zPNWnTmGysVCH6oECy29bMhX6iy');
renderApi.updateEnvVar({value: 'aaaaa'}, {
  serviceId: 'srv-cseq2m5svqrc73f7ai5g',
  envVarKey: 'JWT_SECRET'
})
  .then(({ data }) => {
	  console.log(data));

  }
  .catch(err => console.error(err)
	
	);
