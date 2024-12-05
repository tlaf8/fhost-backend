const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const argon = require('argon2');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const multer = require('multer');
const path = require('path');
const mime = require('mime-types');

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error('Missing JWT_SECRET');
    process.exit(1);
}

async function storeUser(username, email, password, dirname) {
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
            'INSERT INTO login (username, email, password, salt, dirname) VALUES (?, ?, ?, ?, ?)',
            [username, email, hashedPassword, salt.toString('hex'), dirname],
            (err) => {
                if (err) console.error('Error writing to database:', err);
            }
        );

        try {
            if (!fs.existsSync(`cdn/${dirname}`)) {
                fs.mkdirSync(`cdn/${dirname}`);
                fs.mkdirSync(`cdn/${dirname}/thumbnail`);
                fs.mkdirSync(`cdn/${dirname}/src`);
            }
        } catch (err) {
            console.error(err);
        }

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
            db.get('SELECT id, dirname, password, salt FROM login WHERE username = ?', [username], (err, row) => {
                if (err) return reject(err);
                resolve(row);
            });
        });

        db.close();

        if (!row) return false;

        const saltBuffer = Buffer.from(row.salt, 'hex');
        const passwordMatch = await argon.verify(row.password, password, {salt: saltBuffer});

        return (passwordMatch) ? {
            userId: row.id,
            userDir: row.dirname
        } : false;
    } catch (err) {
        console.error('Error verifying login:', err);
        return false;
    }
}

function generateToken(userId, username, userDir) {
    const payload = {userId, username, userDir};
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

const validateStaticFileAccess = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1] || req.query.token;

    if (!token) {
        return res.status(401).json({message: 'No Authorization token'});
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const requestedDir = req.params.userDir;
        if (requestedDir !== decoded.userDir) {
            return res.status(403).json({message: 'Unauthorized access'});
        }

        next();
    } catch (err) {
        return res.status(401).json({message: 'Authentication failed'});
    }
};

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const { dirname } = req.params;
        const sanitizedDirname = path.basename(dirname);
        const uploadPath = path.join(__dirname, 'cdn', sanitizedDirname, 'src');
        if (!fs.existsSync(uploadPath)) {
            fs.mkdirSync(uploadPath, { recursive: true });
        }
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        const { dirname } = req.params;
        const sanitizedDirname = path.basename(dirname);
        const uploadPath = path.join(__dirname, 'cdn', sanitizedDirname, 'src');
        const originalName = path.basename(file.originalname, path.extname(file.originalname));
        const extension = path.extname(file.originalname);

        let finalName = `${originalName}${extension}`;
        let counter = 1;

        while (fs.existsSync(path.join(uploadPath, finalName))) {
            finalName = `${originalName} (${counter})${extension}`;
            counter++;
        }

        cb(null, finalName);
    }
});

const app = express();
const upload = multer({ storage });

const use_cors = false;
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
app.use('/cdn/:userDir/src', validateStaticFileAccess);
app.use('/cdn/:userDir/compressed', validateStaticFileAccess);
app.use('/cdn', express.static(path.join(__dirname, 'cdn')));

app.post('/api/login', async (req, res) => {
    const {username, password} = req.body;

    const { userId, userDir } = await verifyLogin(username, password);

    if (userId && userDir) {
        const token = generateToken(userId, username, userDir);
        return res.status(200).json({token});
    } else {
        return res.status(401).json({message: 'Invalid credentials'});
    }
});

app.post('/api/register', async (req, res) => {
    const {username, email, password} = req.body;
    await storeUser(username, email, password, crypto.randomBytes(32).toString('hex'));
    res.status(200).json({message: 'Registration successful'});
});

app.get('/api/validate', authenticateToken, (req, res) => {
    res.json({
        userId: req.user.userId,
        username: req.user.username,
        userDir: req.user.userDir,
    });
});

app.get('/api/:dirname', authenticateToken, (req, res) => {
    const { dirname } = req.params;
    const { dir } = req.query;
    const sanitizedDirname = path.basename(dirname);
    const filePath = path.join(__dirname, 'cdn', sanitizedDirname, dir);
    res.status(200).json({ files: fs.readdirSync(filePath) });
});

app.post('/api/upload/:dirname', authenticateToken, upload.single('file'), (req, res) => {
    res.status(200).json({ message: 'File uploaded successfully', file: req.file });
});

const port = 9999;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
