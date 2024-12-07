
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

exports.fetchCertificate  = async (req, res) => {
    console.log('fetchCertificate');
	try {
          const domain = 'android-notification.onrender.com'; // Replace with your domain
	        const options = {
	            hostname: domain,
	            port: 443,
	            method: 'GET',
	            rejectUnauthorized: false, // Use cautiously in production
	        };

        const certificatePromise = new Promise((resolve, reject) => {
            const req = https.request(options, (response) => {
                const cert = response.socket.getPeerCertificate();
                if (!cert || Object.keys(cert).length === 0) {
                    return reject(new Error('No certificate retrieved'));
                }
                resolve(cert);
            });

            req.on('error', (e) => {
		     console.log('fetchCertificate : certificatePromise : error : ', e.message);
                reject(e);
            });

            req.end();
        });

        const cert = await certificatePromise;

        // Convert to Base64 format
        const hexToBase64 = (hexString) => {
            const buffer = Buffer.from(hexString.replace(/:/g, ''), 'hex');
            return buffer.toString('base64');
        };

        const sha256FingerprintBase64 = `sha256/${hexToBase64(cert.fingerprint256)}`;
        console.log('sha256FingerprintBase64 :', sha256FingerprintBase64);
        // Send the response
        res.status(200).json({
            domain,
            sha256Fingerprint: sha256FingerprintBase64,
        });
    } catch (error) {
        console.error('Error fetching certificate:', error);
        res.status(500).json({ message: 'Failed to fetch certificate', error: error.message });
    }
};

exports.storeCertificate = async (req, res) => {
    try {
        const { domain, sha256Fingerprint } = req.body; // Expect domain and pin from the request body

        if (!domain || !sha256Fingerprint) {
            return res.status(400).json({ error: 'Domain and SHA256 fingerprint are required.' });
        }

        const query = `
            INSERT INTO pins (domain, sha_256, updated_at)
            VALUES ($1, $2, NOW())
            ON CONFLICT (domain)
            DO UPDATE SET
                sha_256 = EXCLUDED.sha_256,
                updated_at = NOW()
            RETURNING *;
        `;

        const values = [domain, sha256Fingerprint];

        const result = await pool.query(query, values);

        res.status(200).json({
            message: 'Certificate stored successfully',
            data: result.rows[0],
        });
    } catch (error) {
        console.error('Error storing certificate:', error);
        res.status(500).json({ error: 'Failed to store certificate.' });
    }
};


exports.fetchStoreCertificate = async () => {
	console.log('fetchStoreCertificate');
    try {
        // Step 1: Fetch the Certificate
        const certificatePromise = new Promise((resolve, reject) => {
            const options = {
                hostname: domain,
                port: 443,
                method: 'GET',
            };

            const req = https.request(options, (res) => {
                const cert = res.socket.getPeerCertificate();
                if (cert) {
                    resolve(cert);
                } else {
                    reject(new Error('No certificate found'));
                }
            });

            req.on('error', (error) => {
                reject(error);
            });

            req.end();
        });

        const cert = await certificatePromise;

        // Step 2: Compute the SHA256 fingerprint in Base64
        const sha256Fingerprint = `sha256/${crypto
            .createHash('sha256')
            .update(cert.raw)
            .digest('base64')}`;

        console.log('Fetched Certificate SHA256 Fingerprint:', sha256Fingerprint);

        // Step 3: Send the Data to Store Certificate Endpoint
        const response = await fetch(STORE_CERTIFICATE_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${JWT_TOKEN}`,
            },
            body: JSON.stringify({
                domain,
                sha256Fingerprint,
            }),
        });

        if (!response.ok) {
            throw new Error(`Failed to store certificate: ${response.statusText}`);
        }

        const result = await response.json();
        console.log('Certificate stored successfully:', result);
    } catch (error) {
        console.error('Error in fetchAndStoreCertificate:', error);
    }
};

