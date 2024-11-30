const express = require('express');
const axios = require('axios');
const sqlite3 = require('sqlite3').verbose();
const argon = require('argon2');
const crypto = require('crypto');

async function storePassword(username, email, password) {
    try {
        const salt = crypto.randomBytes(16);
        const hashedPassword = await argon.hash(password, {
            salt: salt,
            type: argon.argon2id,
            memoryCost: 2 ** 16,
            timeCost: 3,
            parallel: true
        });

        const db = new sqlite3.Database('fhost.db', (err) => {
            if (err) {
                console.error('Error opening database:', err);
            }
        });

        db.run('INSERT INTO login (username, email, password, salt) VALUES (?, ?, ?, ?)', [
            username,
            email,
            hashedPassword,
            salt.toString('hex')
        ], (err) => {
            if (err) {
                console.error('Error writing to database:', err);
                db.close();
                return;
            }
            console.log('Login info saved successfully.');
        })

        db.close();
    } catch (err) {
        console.error('Error storing login information:', err);
    }
}

async function verifyLogin(username, password) {
    try {
        const db = new sqlite3.Database('fhost.db', (err) => {
            if (err) {
                console.error('Error opening database:', err);
            }
        });

        const row = await new Promise((resolve, reject) => {
            db.get('SELECT password, salt FROM login WHERE username = ?', [username], (err, row) => {
                if (err) {
                    console.error('Error reading database:', err);
                    db.close();
                    reject(err);
                } else {
                    db.close();
                    resolve(row);
                }
            });
        });

        if (!row) {
            console.log('User not found.');
            return false;
        }

        const saltBuffer = Buffer.from(row.salt, 'hex');
        return await argon.verify(row.password, password, {salt: saltBuffer});
    } catch (err) {
        console.error('Error verifying login:', err);
    }
}

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

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (await verifyLogin(username, password)) {
        res.status(200).send("ok");
    } else {
        res.status(401).send("Not authorized");
    }
});

app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    await storePassword(username, email, password);
    res.status(200).send("ok");
})

const port = 9999;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
