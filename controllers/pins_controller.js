
require('dotenv').config();
const pool   = require('../db'); // Assuming you use a database pool for Postgres or MySQL
const bcrypt = require('bcryptjs');
const jwt    = require('jsonwebtoken');
const crypto = require('crypto');
const https  = require('https');

const JWT_SECRET     	    = process.env.JWT_SECRET;
const STORE_CERTIFICATE_URL = 'https://android-notification.onrender.com/pins/store-certificate'; // Replace with your actual endpoint
const domain                = 'android-notification.onrender.com'; // Replace with your actual domain


const REFRESH_EXPIRY = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days in the future
const JWT_EXPIRY     = '1d'; 
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
	
    onsole.log('get pins : user_id = ', userId, '\n');

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

// Fetch Certificate (Logic Only)
exports.fetchCertificate = async (req, res) => {
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
                if (cert) {
                    resolve(cert);
                } else {
                    reject(new Error('No certificate found'));
                }
            });

            request.on('error', (error) => {
                reject(error);
            });

            request.end();
        });

        const cert = await certificatePromise;

        const sha256Fingerprint = `sha256/${crypto
            .createHash('sha256')
            .update(cert.raw)
            .digest('base64')}`;

        // If `res` exists (indicating a direct route invocation), respond with the result
        if (res) {
            res.json({ domain, sha256Fingerprint });
        }

        // Always return the result for internal use
        return { domain, sha256Fingerprint };
    } catch (error) {
        console.error('Error fetching certificate:', error);

        // Send a response only if `res` is provided (direct invocation)
        if (res) {
            res.status(500).json({ error: 'Failed to fetch certificate' });
        }

        // Re-throw the error to allow the caller to handle it
        throw error;
    }
};


// Store Certificate (Logic Only). If it is running separately, provide : domain, sha256Fingerprint.
exports.storeCertificate = async (domain, sha256Fingerprint) => {
    try {
        const query = `
            INSERT INTO pins (domain, sha_256, updated_at)
            VALUES ($1, $2, NOW())
            ON CONFLICT (domain) DO UPDATE
            SET sha_256 = $2, updated_at = NOW();
        `;
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
    try {
        // Step 1: Fetch Certificate
        const { domain, sha256Fingerprint } = await exports.fetchCertificate(req, res);

        // Step 2: Store Certificate
        await exports.storeCertificate(domain, sha256Fingerprint);

        // Respond with success
        res.json({ success: true, domain, sha256Fingerprint });
    } catch (error) {
        console.error('Error in fetchStoreCertificate:', error);
        res.status(500).json({ error: 'Failed to fetch and store certificate' });
    }
};
