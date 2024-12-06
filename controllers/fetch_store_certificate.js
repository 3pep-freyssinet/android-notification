// Fetch and store in one script
const fetchCertificate = require('./fetch_certificate');
const storeCertificate = require('./store_certificate');

module.exports = async (req, res) => {
    try {
        const certificate = await fetchCertificate();
        await storeCertificate({ domain: 'android-notification.onrender.com', certificate });
        res.json({ message: 'Certificate fetched and stored successfully.' });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: 'Error fetching or storing certificate.' });
    }
};
