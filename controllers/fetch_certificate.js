require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const { exec } = require('child_process');
const pool   = require('../db'); // Assuming you use a database pool for Postgres or MySQL
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const JWT_SECRET 		= process.env.JWT_SECRET;

// Middleware to verify JWT
const verifyToken = (req) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        throw new Error('Unauthorized: No token provided');
    }

    const token = authHeader.split(' ')[1];

    return new Promise((resolve, reject) => {
        jwt.verify(token, SECRET_KEY, (err, user) => {
            if (err) {
                return reject(new Error('Unauthorized: Invalid token'));
            }
            resolve(user); // Attach user info from the token
        });
    });
};

// Function to fetch the certificate
module.exports = async (req, res) => {
    try {
        // Verify JWT token
        await verifyToken(req);

        // Define the domain to fetch the certificate for
        const domain = 'your-domain.com'; // Replace with your domain
        const command = `echo | openssl s_client -showcerts -servername ${domain} -connect ${domain}:443 2>/dev/null | openssl x509 -inform pem -noout -pubkey | openssl rsa -pubin -outform der 2>/dev/null | openssl dgst -sha256 -binary | openssl enc -base64`;

        // Execute the command
        exec(command, (err, stdout, stderr) => {
            if (err) {
                console.error('Error fetching certificate:', err);
                return res.status(500).send('Failed to fetch certificate');
            }

            const sha256Pin = `sha256/${stdout.trim()}`;
            res.json({ domain, sha256Pin });
        });
    } catch (err) {
        console.error('Error:', err.message);
        res.status(401).send(err.message);
    }
};
