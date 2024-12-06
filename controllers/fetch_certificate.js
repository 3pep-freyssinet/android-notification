const https  = require('https');
const crypto = require('crypto');

//module.exports = async (req, res) => {
exports.fetchCertificate = async (req, res) => {
    try {
        const domain = 'android-notification.onrender.com'; // Update with your domain
        const options = { hostname: domain, port: 443, method: 'GET' };

        const certificate = await new Promise((resolve, reject) => {
            const req = https.request(options, (res) => {
                const cert = res.socket.getPeerCertificate();
                if (!cert || !cert.raw) {
                    return reject(new Error('Failed to fetch certificate.'));
                }

                const sha256 = crypto.createHash('sha256').update(cert.raw).digest('base64');
                resolve(`sha256/${sha256}`);
            });

            req.on('error', (e) => reject(e));
            req.end();
        });

        res.json({ domain, certificate });
    } catch (error) {
        console.error('Error fetching certificate:', error);
        res.status(500).json({ error: 'Error fetching certificate.' });
    }
};
