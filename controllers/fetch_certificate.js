const express = require('express');
const jwt = require('jsonwebtoken');
const { exec } = require('child_process');

const app = express();

const SECRET_KEY = 'your_jwt_secret_key'; // Use a strong secret key for JWT signing

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).send('Unauthorized: No token provided');
    }

    const token = authHeader.split(' ')[1];

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            return res.status(403).send('Unauthorized: Invalid token');
        }
        req.user = user; // Attach the user info from the token
        next();
    });
};

// Endpoint to fetch the certificate using OpenSSL
app.get('/api/fetch-certificate', verifyToken, (req, res) => {
    const domain = 'your-domain.com'; // Replace with your domain
    const command = `echo | openssl s_client -showcerts -servername ${domain} -connect ${domain}:443 2>/dev/null | openssl x509 -inform pem -noout -pubkey | openssl rsa -pubin -outform der 2>/dev/null | openssl dgst -sha256 -binary | openssl enc -base64`;

    exec(command, (err, stdout, stderr) => {
        if (err) {
            console.error('Error fetching certificate:', err);
            return res.status(500).send('Failed to fetch certificate');
        }

        const sha256Pin = `sha256/${stdout.trim()}`;
        res.json({ domain, sha256Pin });
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
