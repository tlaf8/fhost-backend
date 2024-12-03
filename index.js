const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const argon = require('argon2');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const app = express();

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error('Missing JWT_SECRET');
    process.exit(1);
}

const use_cors = true;
if (use_cors) {
    app.use((req, res, next) => {
        res.header('Access-Control-Allow-Origin', '*');
        res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
        next();
    });
}

app.use(express.urlencoded({extended: true}));
app.use(express.json());

async function storePassword(username, email, password) {
    try {
        const salt = crypto.randomBytes(16);
        const hashedPassword = await argon.hash(password, {
            salt: salt,
            type: argon.argon2id,
            memoryCost: 2 ** 16,
            timeCost: 3,
            parallelism: 1,
        });

        const db = new sqlite3.Database('fhost.db', (err) => {
            if (err) console.error('Error opening database:', err);
        });

        db.run(
            'INSERT INTO login (username, email, password, salt) VALUES (?, ?, ?, ?)',
            [username, email, hashedPassword, salt.toString('hex')],
            (err) => {
                if (err) console.error('Error writing to database:', err);
            }
        );

        db.close();
    } catch (err) {
        console.error('Error storing login information:', err);
    }
}

async function verifyLogin(username, password) {
    try {
        const db = new sqlite3.Database('fhost.db', (err) => {
            if (err) console.error('Error opening database:', err);
        });

        const row = await new Promise((resolve, reject) => {
            db.get('SELECT id, password, salt FROM login WHERE username = ?', [username], (err, row) => {
                if (err) return reject(err);
                resolve(row);
            });
        });

        db.close();

        if (!row) return false;

        const saltBuffer = Buffer.from(row.salt, 'hex');
        const passwordMatch = await argon.verify(row.password, password, {salt: saltBuffer});

        if (passwordMatch) return row.id;
        else return false;
    } catch (err) {
        console.error('Error verifying login:', err);
        return false;
    }
}

function generateToken(userId, username) {
    const payload = {userId, username};
    return jwt.sign(payload, JWT_SECRET, {expiresIn: '1h'});
}

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];

    if (!authHeader) {
        console.log("No Authorization Header Present");
        return res.status(401).json({message: 'No Authorization header'});
    }

    const token = authHeader.split(' ')[1];

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            console.log("Token Verification Error Details:", {
                name: err.name,
                message: err.message,
                expiredAt: err.expiredAt
            });
            return res.status(401).json({message: 'Authentication failed'});
        }

        req.user = decoded;
        next();
    });
};

app.post('/api/login', async (req, res) => {
    const {username, password} = req.body;

    const userId = await verifyLogin(username, password);

    if (userId) {
        const token = generateToken(userId, username);
        console.error(token);
        return res.status(200).json({token});
    } else {
        return res.status(401).json({message: 'Invalid credentials'});
    }
});

app.post('/api/register', async (req, res) => {
    const {username, email, password} = req.body;
    await storePassword(username, email, password);
    res.status(200).json({message: 'Registration successful'});
});

app.get('/api/protected', authenticateToken, (req, res) => {
    res.json({
        message: 'This is protected data',
        userId: req.user.userId,
    });
});

// Start the server
const port = 9999;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
