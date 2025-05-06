/* test
curl -X POST -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiY3Jvbi1qb2Itc2VydmljZSIsInJvbGUiOiJjcm9uIiwiaWF0IjoxNzMzNjQ4NjkxLCJleHAiOjE3MzYyNDA2OTF9.Y-vu3nzNmwoJQT-hKeJstQ17LpEqdkuy-xlWzhbOYIE" 
-H "Content-Type: application/json" 
https://android-notification.onrender.com/pins/fetch-store-certificate
*/

require('dotenv').config();
const pool   = require('../db'); // Assuming you use a database pool for Postgres or MySQL
const bcrypt = require('bcryptjs');
const jwt    = require('jsonwebtoken');
const crypto = require('crypto');
const https  = require('https');

const JWT_SECRET     	    = process.env.JWT_SECRET;
const STORE_CERTIFICATE_URL = 'https://android-notification.onrender.com/pins/store-certificate'; // Replace with your actual endpoint
const domain                = 'android-notification.onrender.com'; // Replace with your actual domain


//const REFRESH_EXPIRY = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days in the future
//const JWT_EXPIRY     = '1d'; 

const JWT_EXPIRY 		= process.env.JWT_EXPIRY;
const REFRESH_EXPIRY 		= process.env.JWT_REFRESH_EXPIRY;

const ALERT_TIME     = 3 * 24 * 60 * 60 * 1000 //3 days, trigger

//console.log('process.env.DATABASE_URL = ' + process.env.DATABASE_URL);
console.log('pool = ' + pool);

// Get SHA256 pins
exports.getPins = async (req, res) => {
    // get pins endpoint
    
    console.log('get pins \n');
	
    //const pins = req.body.pins;
	
    //console.log("get pins : pins : ", pins );
    const userId = req.user.userId; // Assuming user ID comes from middleware after verifying the JWT
	
    console.log('get pins : user_id = ', userId, '\n');

try {
        const result = await pool.query('SELECT domain, sha256_pin FROM pins');
        res.json(result.rows);

	console.log('get pins / : result : ', JSON.stringify(result));

    	if(result.rowCount == 1){
		console.log('get pins successfull : pins : ', result.rows[0].sha256_pin);
	    	res.status(200).json({ 
			message: 'get pins successfull', 
			pins:result.rows[0].sha256_pin
		});
    	}else{
		console.log('get pins failed');
	    	res.status(500).send('Internal server error : Error getting pins');
    	}
	
    } catch (err) {
        console.error('Error fetching pins:', err);
        res.status(500).send('Server Error');
    }
};

exports.getLatestSHA256Pin = async (req, res) => {
    console.log('getLatestSHA256Pin : start');
try {
        const result = await pool.query(
            'SELECT sha256_pin FROM pins ORDER BY updated_at DESC LIMIT 1'
        );
        if (result.rows.length > 0) {
            res.json({ sha256: result.rows[0].sha256_pin });
        } else {
            res.status(404).json({ error: 'No pins found in the database' });
        }
    } catch (error) {
        console.error('Error fetching latest pin:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}

// Renew SHA256 pin certificate
exports.renewSHA256Certificate = async (req, res) => {
    console.log('renewSHA256Certificate : start');
    //console.log("renewSHA256Certificate : Headers received:", req.headers);
    //console.log('renewSHA256Certificate req.user : ', JSON.stringify(req.user));
    
    console.log('renewSHA256Certificate user_id : ', req.user.userId, ' username : ', req.user.username);

    const user_id = req.user.userId;
    try {
        const domain = req.query.domain || 'android-notification.onrender.com'; // Accept domain as query param
	console.log('renewSHA256Certificate : domain : ', domain);
        const cert = await new Promise((resolve, reject) => {
            const options = {
                hostname: domain,
                port: 443,
                method: 'GET',
		agent: false,
		//secureProtocol: 'TLSv1_2_method',
    		//ciphers: 'ALL'
            };

            const request = https.request(options, (response) => {
                const cert = response.socket.getPeerCertificate();
		//console.log('renewSHA256Certificate : cert : ', cert);
                if (Object.keys(cert).length === 0) {
                    reject(new Error('The certificate was empty or unavailable.'));
                } else {
                    resolve(cert);
                }
            });

            request.on('error', (error) => {
                reject(error);
            });

            request.end();
        });

        const sha256Fingerprint = `sha256/${crypto
            .createHash('sha256')
            .update(cert.raw)
            .digest('base64')}`;

        console.log('RenewSHA256Certificate : sha256Fingerprint : ', sha256Fingerprint);

	//store the sha256Fingerprint in database
	const updated_at             = new Date(Date.now());
	const expires_at = new Date();
        expires_at.setDate(expires_at.getDate() + 30); // Expire in 30 days
	
	const storeSHA256Certificate = await exports.storeCertificate(user_id, sha256Fingerprint, updated_at, expires_at); 
	  
        console.log('RenewSHA256Certificate :storeSHA256Certificate : ', storeSHA256Certificate);

	if(storeSHA256Certificate.success){
		// Send a successful response
		 console.log('RenewSHA256Certificate :storeSHA256Certificate.success : ', storeSHA256Certificate.success);
        	res.status(200).json({
            		message: 'Success renewal',
            		domain,
            		sha256: sha256Fingerprint,
        	});
	}
    } catch (error) {
        console.error('Error renew certificate:', error);

        // Respond with an error message
        res.status(500).json({
            message: 'Failed to renew SHA256 certificate',
            error: error.message,
        });
    }
};
///////////////////////////////////////
/////////////////////////// get latest sha-256 pin /////////////////////////////////
// Fetch the latest SHA-256 pin
const fetchLatestPin = async (userId) => {
    return new Promise((resolve, reject) => {
        console.log('fetchLatestPin, start ...');
	const domain = 'android-notification.onrender.com';
	//const options = { hostname: domain, port: 443, method: 'GET' };
	    
	const options = {
    		hostname: domain,
    		port: 443,
    		method: 'GET',
    		agent: new https.Agent({  
        		// Force Node.js to fetch the leaf cert
        		rejectUnauthorized: false, // Only for debugging! Remove in prod.
        		requestCert: true,
    		}),
	};
	const forge = require('node-forge');
	    
        const request = https.request(options, (response) => {
            const cert = response.socket.getPeerCertificate();
	   //console.log('fetchLatestPin, cert : ', cert);
            if (!cert || Object.keys(cert).length === 0) {
                //reject(new Error('No certificate available'));
		console.warn('fetchLatestPin: No certificate available, using last known valid pin');
                resolve(getCachedPin(userId)); // Use cached pin if available.
            } else {
                const sha256Fingerprint = `sha256/${crypto.createHash('sha256').update(cert.raw).digest('base64')}`;
                resolve(sha256Fingerprint);

		//cachePin(sha256Fingerprint); // Store for future use
                //resolve(sha256Fingerprint);
            }
        });
	
	/*    
//const https = require('https');
const options = {
    hostname: 'android-notification.onrender.com',
    servername: 'android-notification.onrender.com', // Force SNI
    port: 443,
    method: 'GET',
    agent: new https.Agent({  
        rejectUnauthorized: false, // For testing only
    }),
};

const forge = require('node-forge');
	    
const request = https.request(options, (response) => {
    const cert = response.socket.getPeerCertificate(true);
    
    if (!cert || !cert.pem) {
        console.warn('No certificate available');
        return resolve(getCachedPin());
    }

    // Parse PEM and extract DER public key (matches OpenSSL)
    const pem = cert.pem.replace(/^\-+BEGIN CERTIFICATE\-+\r?\n|\-+END CERTIFICATE\-+\r?\n?/g, '');
    const der = Buffer.from(pem, 'base64');
    const asn1 = forge.asn1.fromDer(forge.util.createBuffer(der.toString('binary')));
    const x509 = forge.pki.certificateFromAsn1(asn1);
    const publicKeyDer = forge.pki.publicKeyToAsn1(x509.publicKey).getBytes();
    
    // Hash the DER key
    const hash = crypto.createHash('sha256')
        .update(Buffer.from(publicKeyDer, 'binary'))
        .digest('base64');
    
    const okHttpPin = `sha256/${hash}`;
    console.log('DER Public Key Pin:', okHttpPin); // Now matches OpenSSL
    resolve(okHttpPin);
});
	*/
        //console.log('fetchLatestPin, request : ', request);
        request.on('error', (error) => {
            console.error('fetchLatestPin Error:', error);
            resolve(getCachedPin(userId)); // Use cached pin if fetch fails
        });
        request.end();
    });
};

// Store last known valid pin
//let cachedPin = null;
//const cachePin = (pin) => {
//    cachedPin = pin;
//};

const getCachedPin = async (userId) => {
    try {
	console.log('getCachedPin, start ...');
        const res = await pool.query(`SELECT sha256_pin FROM pins WHERE user_id = $1;`, [userId]);
	if(res.rows.length > 0){
	   console.log('getCachedPin, sha256_pin :', res.rows[0].sha256_pin);
	}else{
	   console.log('getCachedPin, sha256_pin :', null);
	}
        
	return res.rows.length ? res.rows[0].sha256_pin : null;
    } catch (error) {
        console.error('Error fetching cached pin from DB:', error);
        return null;
    }
};


// API endpoint to get the latest SHA-256 pin

exports.fetchCertificate =  async (userId, req, res) => {
    console.log('fetchCertificate, start... '); 

    console.log('fetchCertificate, userId : ', userId); 

    if(userId == null){
	console.log('fetchCertificate, no userId found'); 
	return res.status(500).json({ error: 'cannot get valid SHA pin for unknown user' });    
    }

    //here, there is a 'userId'
    try {
        const pin = await fetchLatestPin(userId);
	console.log('fetchCertificate, pin : ', pin);  
	if (!pin) {
            console.warn('fetchCertificate: No valid SHA pin available.');
            return res.status(500).json({ error: 'No valid SHA pin available' });
        }
        //res.json({ sha256Pin: pin });
	return { sha256Pin: pin }; 
    } catch (error) {
        //res.status(500).json({ error: 'Failed to fetch certificate' });
	console.error('fetchCertificate :  Failed to fetch certificate ');     
	return { error: 'Failed to fetch certificate' };
    }
}
//////////////////////////////////////
// Fetch Public Key SHA-256 for Pinning
exports.fetchCertificate_marche = async (req, res) => {
    console.log('fetchCertificate : start');

    try {
        const domain = req.query.domain || 'android-notification.onrender.com'; // Accept domain as query param

        const certificatePromise = new Promise((resolve, reject) => {
            const options = {
                hostname: domain,
                port: 443,
                method: 'GET',
            };

            const request = https.request(options, (response) => {
                const cert = response.socket.getPeerCertificate();
                if (!cert || !cert.raw) {
                    reject(new Error('The certificate was empty or unavailable.'));
                } else {
                    resolve(cert);
                }
            });

            request.on('error', (error) => reject(error));
            request.end();
        });

        const cert = await certificatePromise;

        // Convert the certificate to PEM format
        const certPem = `-----BEGIN CERTIFICATE-----\n${cert.raw.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----`;

        // Create a public key object from the certificate
        const publicKeyObj = crypto.createPublicKey(certPem);

        // Export the public key in SubjectPublicKeyInfo (SPKI) DER format
        const publicKeyDer = publicKeyObj.export({ type: 'spki', format: 'der' });

        // Compute SHA-256 fingerprint
        const sha256Fingerprint = `sha256/${crypto.createHash('sha256').update(publicKeyDer).digest('base64')}`;

        console.log('fetchCertificate : sha256Fingerprint :', sha256Fingerprint);

        // Set expiration date for reference
        const expiration = new Date();
        expiration.setDate(expiration.getDate() + 30); // Expire in 30 days

	/*
        // Return response
        return res.json({
            domain,
            sha256Fingerprint,
            expiration
        });
	*/
	    
         return {domain, sha256Fingerprint, expiration};
	    
    } catch (error) {
        console.error('Error fetching certificate:', error);
        //return res.status(500).json({ error: 'Failed to fetch certificate' });
	return { error: 'Failed to fetch certificate' };    
    }
};

// Fetch Public Key SHA-256 for Pinning
exports.fetchCertificate_5 = async (req, res) => {
    console.log('fetchCertificate : start');

    try {
        const domain = req.query.domain || 'android-notification.onrender.com'; // Accept domain as query param

        const certificatePromise = new Promise((resolve, reject) => {
            const options = {
                hostname: domain,
                port: 443,
                method: 'GET',
            };

            const request = https.request(options, (response) => {
                const cert = response.socket.getPeerCertificate();
                if (!cert || !cert.raw) {
                    reject(new Error('The certificate was empty or unavailable.'));
                } else {
                    resolve(cert);
                }
            });

            request.on('error', (error) => reject(error));
            request.end();
        });

        const cert = await certificatePromise;

        // Extract and hash the public key (SPKI format)
        const publicKeyDer = crypto.createPublicKey(cert.pubkey).export({ type: 'spki', format: 'der' });
        const sha256Fingerprint = `sha256/${crypto.createHash('sha256').update(publicKeyDer).digest('base64')}`;

        console.log('fetchCertificate : sha256Fingerprint :', sha256Fingerprint);

        // Set expiration date for reference
        const expiration = new Date();
        expiration.setDate(expiration.getDate() + 30); // Expire in 30 days

        // Return response
        return res.json({
            domain,
            sha256Fingerprint,
            expiration
        });

    } catch (error) {
        console.error('Error fetching certificate:', error);
        return res.status(500).json({ error: 'Failed to fetch certificate' });
    }
};


exports.fetchCertificate_4 = async (req, res) => {
    console.log('fetchCertificate : start');
    
    try {
        const domain = req.query.domain || 'android-notification.onrender.com';

        const certificatePromise = new Promise((resolve, reject) => {
            const options = {
                hostname: domain,
                port: 443,
                method: 'GET',
            };

            const request = https.request(options, (response) => {
                const cert = response.socket.getPeerCertificate();
                if (!cert || Object.keys(cert).length === 0) {
                    reject(new Error('The certificate was empty or unavailable.'));
                } else {
                    resolve(cert);
                }
            });

            request.on('error', (error) => {
                reject(error);
            });

            request.end();
        });

        const cert = await certificatePromise;

        console.log('fetchCertificate : Full Certificate Chain :', cert);

        // Correct way to hash the certificate public key
        const publicKeyDer = cert.raw;  // This should be the correct public key
        const sha256Fingerprint = `sha256/${crypto
            .createHash('sha256')
            .update(publicKeyDer)
            .digest('base64')}`;
        console.log('fetchCertificate : Full Certificate:', cert);
        console.log('fetchCertificate : Corrected sha256Fingerprint : ', sha256Fingerprint);

        return { domain, sha256Fingerprint };
    } catch (error) {
        console.error('Error fetching certificate:', error);
        throw error;
    }
};


exports.fetchCertificate_3 = async (req, res) => {
    console.log('fetchCertificate : start');
	
    try {
        const domain = req.query.domain || 'android-notification.onrender.com';

        const certificatePromise = new Promise((resolve, reject) => {
            const options = {
                hostname: domain,
                port: 443,
                method: 'GET',
            };

            const request = https.request(options, (response) => {
                const cert = response.socket.getPeerCertificate();
                if (Object.keys(cert).length === 0) {
                    reject(new Error('The certificate was empty or unavailable.'));
                } else {
                    resolve(cert);
                }
            });

            request.on('error', (error) => {
                reject(error);
            });

            request.end();
        });

        const cert = await certificatePromise;

        // Convert public key to DER format and hash it
        const publicKey = cert.pubkey; // This should be the public key in PEM format
        const publicKeyDER = Buffer.from(publicKey, 'base64'); // Convert to DER format
        const sha256Fingerprint = `sha256/${crypto
            .createHash('sha256')
            .update(publicKeyDER)
            .digest('base64')}`;

        console.log('fetchCertificate : Corrected sha256Fingerprint : ', sha256Fingerprint);

        return { domain, sha256Fingerprint };
    } catch (error) {
        console.error('Error fetching certificate:', error);
        throw error;
    }
};

// Fetch Certificate (Logic Only) : get sha256 pin from server
exports.fetchCertificate__ = async (req, res) => {
    console.log('fetchCertificate : start');
	
    try {
        const domain = req.query.domain || 'android-notification.onrender.com'; // Accept domain as query param

        const certificatePromise = new Promise((resolve, reject) => {
            const options = {
                hostname: domain,
                port: 443,
                method: 'GET',
            };

            const request = https.request(options, (response) => {
                const cert = response.socket.getPeerCertificate();
               if (Object.keys(cert).length === 0) {
                    reject(new Error('The certificate was empty or unavailable.'));
                } else {
                    resolve(cert);
                }
            });

            request.on('error', (error) => {
                reject(error);
            });

            request.end();
        });

        const cert = await certificatePromise;
        //console.log('fetchCertificate : cert : ', cert);
        const sha256Fingerprint = `sha256/${crypto
            .createHash('sha256')
            .update(cert.raw)
            .digest('base64')}`;
	    
	console.log('fetchCertificate : sha256Fingerprint : ', sha256Fingerprint);

	/*
        // If `res` exists (indicating a direct route invocation), respond with the result
        if (res) {
            res.json({ domain, sha256Fingerprint });
        }
	*/

	//set the expiration date of the sha256 pin
        const expiration = new Date();
        expiration.setDate(expiration.getDate() + 30); // Expire in 30 days
	
        // Always return the result for internal use
        return { domain, sha256Fingerprint, expiration };
    } catch (error) {
        console.error('Error fetching certificate:', error);

	/*
        // Send a response only if `res` is provided (direct invocation)
        if (res) {
            res.status(500).json({ error: 'Failed to fetch certificate' });
        }
	*/
	    
        // Re-throw the error to allow the caller to handle it
        throw error;
    }
};


// Store Certificate (Logic Only). If it is running separately, provide : userId, domain, sha256Fingerprint, updated_at, expires_at.
exports.storeCertificate = async (userId, sha256Fingerprint, updated_at, expires_at) => {

console.log('storeCertificate : userId : ', userId, ' sha256Fingerprint : ', sha256Fingerprint, ' updated_at : ', expires_at);

//const expiration = new Date();
//expiration.setDate(expiration.getDate() + 30); // Expire in 30 days

/*
    await pool.query(
        `INSERT INTO pins (user_id, sha256_pin, updated_at, expires_at) VALUES ($1, $2, NOW(), $3) 
         ON CONFLICT (sha256_pin) DO NOTHING`,
        [sha256Fingerprint, expiration]
    );   
*/
try {
        const query = `
            INSERT INTO pins (sha256_pin, user_id, updated_at, expires_at )
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (user_id) 
	    DO UPDATE SET 
	    sha256_pin = $1, 
	    updated_at = $3,
            expires_at = $4
        `;

	console.log('storeCertificate : sha256Fingerprint : ', sha256Fingerprint, ' userId : ', userId, ' updated_at : ', updated_at, ' expires_at : ', expires_at);
        
	await pool.query(query, [sha256Fingerprint, userId, updated_at, expires_at]);

        console.log('Certificate stored successfully:', { domain, sha256Fingerprint,  updated_at, expires_at});
        return { success: true };
    } catch (error) {
        console.error('Error storing certificate:', error);
        throw error;
    }
};

// Fetch and Store Certificate
exports.fetchStoreCertificate = async (req, res) => {
	console.log('fetchStoreCertificate : start');
try {
	//In case the header is not sent, we cannot access 'userId'. then we get it from database knowing 'androidId' for the the device.
	let userId;
	if(!req.user){
	    const androidId = req.body.androidId;
	    console.log('fetchStoreCertificate : androidId : ', androidId);
	    if(androidId == null){
	       console.warn('fetchStoreCertificate : androidId not found.');
               return res.status(404).json({ message: 'androidId not found' });
	    }
		
	    //get userId from the database
	    const result = await pool.query('SELECT * FROM users_notification WHERE android_id = $1', [androidId]);
	    if (result.rowCount === 0) {
	      console.warn('fetchStoreCertificate : userId not found.');
	      return res.status(404).json({ message: 'userId id not found' });
	    }
		
	    console.log('fetchStoreCertificate : userId retrieved from androidId : ', result.rows[0].id);
	    userId = result.rows[0].id;
	}
	else{
	    userId = req.user.userId;
	    console.log('fetchStoreCertificate : user_id retrieved from the header: ', userId);
	}
    
	//here, there is a 'userId'.
	 console.log('fetchStoreCertificate : user_id before call to fetchCertificate : ', userId);  
	
        // Step 1: Fetch Certificate (create a certificate)
	const certificateResult = await exports.fetchCertificate(userId, req, res);
	
	// Check if an error occurred in fetchCertificate
        if (certificateResult.error) {
            console.error('Error in fetchCertificate:', certificateResult.error);
            return res.status(500).json({ error: certificateResult.error });
        }
        
        const { sha256Pin } = certificateResult;    
	console.log('fetchStoreCertificate : sha256Fingerprint : ', sha256Pin);
	    
        // Step 2: Store Certificate
	const updated_at = new Date(); //now()
	const expires_at = new Date();
	expires_at.setDate(updated_at.getDate() + 30); // Expire in 30 days from the updated date

        await exports.storeCertificate(userId, sha256Pin, updated_at, expires_at);

        // Respond with success
        res.json({ success: true, domain, sha256Pin, expires_at });
    } catch (error) {
        console.error('Error in fetchStoreCertificate:', error);
        res.status(500).json({ error: 'Failed to fetch and store certificate' });
    }
};
