const pool   = require('../db'); 
const { Pool } = require('pg');

/*
// Configure PostgreSQL database connection
const pool = new Pool({
    user: 'your_db_user',
    host: 'your_db_host',
    database: 'your_db_name',
    password: 'your_db_password',
    port: 5432,
});
*/


exports.storeCertificate = async (req, res) => {
    try {
        const { domain, certificate } = req.body; // Input from fetch script
        if (!domain || !certificate) {
            return res.status(400).json({ error: 'Missing domain or certificate.' });
        }

        // Update database
        const result = await pool.query(
            'INSERT INTO pins (domain, sha256_pin) VALUES ($1, $2) ON CONFLICT (domain) DO UPDATE SET sha256_pin = $2',
            [domain, certificate]
        );

        res.json({ message: 'Certificate stored successfully.', result });
    } catch (error) {
        console.error('Error storing certificate:', error);
        res.status(500).json({ error: 'Error storing certificate.' });
    }
};
