const express = require('express');
const axios = require('axios');
const bodyParser = require('body-parser');

const app = express();

const use_cors = true;
if (use_cors) {
    app.use((req, res, next) => {
        res.header('Access-Control-Allow-Origin', '*');
        res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
        next();
    });
}

app.use(bodyParser.json());

app.post('/api/verify', async (req, res) => {
    const { token } = req.body;

    if (!token) {
        return res.status(400).json({ error: 'Token is required' });
    }

    try {
        const response = await axios.get(`https://oauth2.googleapis.com/tokeninfo?id_token=${token}`);
        const { email, name } = response.data;
        return res.json({ email, name });
    } catch (error) {
        console.error('Error verifying token:', error);
        return res.status(401).json({ error: 'Invalid token' });
    }
});

const port = 9999;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
