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
exports.RenewSHA256Certificate = async (req, res) => {
    console.log('RenewSHA256Certificate : start');

    try {
        const domain = req.query.domain || 'android-notification.onrender.com'; // Accept domain as query param

        const cert = await new Promise((resolve, reject) => {
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

        const sha256Fingerprint = `sha256/${crypto
            .createHash('sha256')
            .update(cert.raw)
            .digest('base64')}`;

        console.log('RenewSHA256Certificate : sha256Fingerprint : ', sha256Fingerprint);

        // Send a successful response
        res.status(200).json({
            message: 'Success renewal',
            domain,
            sha256: sha256Fingerprint,
        });
    } catch (error) {
        console.error('Error renew certificate:', error);

        // Respond with an error message
        res.status(500).json({
            message: 'Failed to renew SHA256 certificate',
            error: error.message,
        });
    }
};


// Fetch Certificate (Logic Only)
exports.fetchCertificate = async (req, res) => {
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
        console.log('fetchCertificate : cert : ', cert);
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
	    
        // Always return the result for internal use
        return { domain, sha256Fingerprint };
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


// Store Certificate (Logic Only). If it is running separately, provide : domain, sha256Fingerprint.
exports.storeCertificate = async (domain, sha256Fingerprint) => {
    try {
        const query = `
            INSERT INTO pins (domain, sha256_pin, updated_at)
            VALUES ($1, $2, NOW())
            ON CONFLICT (domain) DO UPDATE
            SET sha256_pin = $2, updated_at = NOW();
        `;

	console.log('storeCertificate : sha256Fingerprint : ', sha256Fingerprint, ' domain : ', domain);
        
	    await pool.query(query, [domain, sha256Fingerprint]);

        console.log('Certificate stored successfully:', { domain, sha256Fingerprint });
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
        // Step 1: Fetch Certificate
        const { domain, sha256Fingerprint } = await exports.fetchCertificate(req, res);
	    
	console.log('fetchStoreCertificate : sha256Fingerprint : ', sha256Fingerprint, ' domain : ', domain);
	    
        // Step 2: Store Certificate
        await exports.storeCertificate(domain, sha256Fingerprint);

        // Respond with success
        res.json({ success: true, domain, sha256Fingerprint });
    } catch (error) {
        console.error('Error in fetchStoreCertificate:', error);
        res.status(500).json({ error: 'Failed to fetch and store certificate' });
    }
};
