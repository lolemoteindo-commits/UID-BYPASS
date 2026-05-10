const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const API_BASE_URL = process.env.API_BASE_URL || 'http://46.250.239.109:6020';

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Too many requests, please try again later.' }
});

app.use(limiter);
app.use(cors());
app.use(express.json());

// Serve static frontend files
app.use(express.static(path.join(__dirname, '../')));

// File-based storage for users
const DATA_FILE = path.join(__dirname, 'users.json');

function loadUsers() {
    try {
        if (fs.existsSync(DATA_FILE)) {
            const data = fs.readFileSync(DATA_FILE, 'utf8');
            return JSON.parse(data);
        }
    } catch (e) {
        console.error('Error loading users:', e);
    }
    return [];
}

function saveUsers(users) {
    try {
        fs.writeFileSync(DATA_FILE, JSON.stringify(users, null, 2));
    } catch (e) {
        console.error('Error saving users:', e);
    }
}

// Initialize users
let users = loadUsers();
const sessions = new Set();

// Admin user (default) - create if not exists
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

if (!users.find(u => u.username === ADMIN_USERNAME)) {
    users.push({
        username: ADMIN_USERNAME,
        password: hashPassword(ADMIN_PASSWORD),
        isAdmin: true
    });
    saveUsers(users);
}

// Password hashing function
function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

// License key storage
const KEYS_FILE = path.join(__dirname, 'keys.json');

function loadKeys() {
    try {
        if (fs.existsSync(KEYS_FILE)) {
            const data = fs.readFileSync(KEYS_FILE, 'utf8');
            return JSON.parse(data);
        }
    } catch (e) {
        console.error('Error loading keys:', e);
    }
    return [];
}

function saveKeys(keys) {
    try {
        fs.writeFileSync(KEYS_FILE, JSON.stringify(keys, null, 2));
    } catch (e) {
        console.error('Error saving keys:', e);
    }
}

// Generate random license key
function generateLicenseKey() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let key = '';
    for (let i = 0; i < 16; i++) {
        key += chars.charAt(Math.floor(Math.random() * chars.length));
        if ((i + 1) % 4 === 0 && i < 15) key += '-';
    }
    return key;
}

// Create default admin key if no keys exist
function initDefaultKey() {
    const keys = loadKeys();
    if (keys.length === 0) {
        const defaultKey = {
            key: 'ADMIN-KEY-1234-5678',
            maxDays: 30,
            createdAt: new Date().toISOString(),
            active: true
        };
        keys.push(defaultKey);
        saveKeys(keys);
        console.log('Default admin key created:', defaultKey.key);
    }
}

// Initialize default key
initDefaultKey();

// Create license key (admin only)
app.post('/api/keys', authMiddleware, (req, res) => {
    const { keyType = 'client' } = req.body;
    
    // Key types: 'free' = 1 day, 'client' = 30 days
    const maxDays = keyType === 'free' ? 1 : 30;
    const keyPrefix = keyType === 'free' ? 'FREE' : 'CLIENT';
    
    let keys = loadKeys();
    const newKey = {
        key: keyPrefix + '-' + generateLicenseKey(),
        maxDays: maxDays,
        keyType: keyType,
        createdAt: new Date().toISOString(),
        active: true
    };
    
    keys.push(newKey);
    saveKeys(keys);
    
    res.json({ success: true, key: newKey });
});

// Get all license keys (admin only)
app.get('/api/keys', authMiddleware, (req, res) => {
    const keys = loadKeys();
    res.json(keys);
});

// Delete license key (admin only)
app.delete('/api/keys/:key', authMiddleware, (req, res) => {
    const { key } = req.params;
    
    let keys = loadKeys();
    const index = keys.findIndex(k => k.key === key);
    
    if (index === -1) {
        return res.status(404).json({ error: 'Key not found' });
    }
    
    keys.splice(index, 1);
    saveKeys(keys);
    
    res.json({ success: true, message: 'Key deleted' });
});

// Validate license key (login)
app.post('/api/validate-key', (req, res) => {
    const { key } = req.body;
    
    if (!key) {
        return res.status(400).json({ error: 'License key required' });
    }
    
    const keys = loadKeys();
    const keyData = keys.find(k => k.key === key && k.active);
    
    if (!keyData) {
        return res.status(401).json({ error: 'Invalid or expired license key' });
    }
    
    // Create session token
    const token = generateToken();
    sessions.add(token);
    
    res.json({
        success: true,
        message: 'Login successful',
        token: token,
        maxDays: keyData.maxDays
    });
});

// Login endpoint
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }
    
    // Reload users from file
    users = loadUsers();
    
    const user = users.find(u => u.username === username && u.password === hashPassword(password));
    
    if (!user) {
        return res.status(401).json({ error: 'Invalid username or password' });
    }
    
    // Create session token
    const token = generateToken();
    sessions.add(token);
    
    res.json({
        success: true,
        message: 'Login successful',
        token: token,
        username: user.username,
        isAdmin: user.isAdmin
    });
});

// Logout endpoint
app.post('/api/logout', (req, res) => {
    const { token } = req.body;
    sessions.delete(token);
    res.json({ success: true, message: 'Logged out' });
});

// Verify session
app.post('/api/verify-session', (req, res) => {
    const { token } = req.body;
    if (sessions.has(token)) {
        res.json({ valid: true });
    } else {
        res.status(401).json({ valid: false, error: 'Invalid session' });
    }
});

// Auth middleware
function authMiddleware(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token || !sessions.has(token)) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    // Check if user is admin (for simplicity, check if username is 'admin')
    // In production, store user info with token
    next();
}

// Get all users (admin only)
app.get('/api/users', authMiddleware, (req, res) => {
    // Reload users from file
    users = loadUsers();
    
    // Return users without passwords
    const userList = users.map(u => ({
        username: u.username,
        isAdmin: u.isAdmin
    }));
    res.json(userList);
});

// Delete user (admin only)
app.delete('/api/users/:username', authMiddleware, (req, res) => {
    const { username } = req.params;
    
    // Reload users from file
    users = loadUsers();
    
    // Prevent deleting admin
    const user = users.find(u => u.username === username);
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }
    
    if (user.isAdmin) {
        return res.status(403).json({ error: 'Cannot delete admin user' });
    }
    
    // Remove user
    const index = users.findIndex(u => u.username === username);
    users.splice(index, 1);
    
    // Save to file
    saveUsers(users);
    
    res.json({ success: true, message: 'User deleted' });
});

// Add days to UID (protected route)
app.post('/api/add-days', authMiddleware, async (req, res) => {
    const { uid, days } = req.body;
    
    if (!uid || !days) {
        return res.status(400).json({ error: 'UID and days required' });
    }
    
    try {
        // Forward request to real API
        const response = await fetch(`${API_BASE_URL}/add-days`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({ uid, days })
        });
        
        const data = await response.json();
        res.json(data);
        
    } catch (error) {
        console.error('API Error:', error);
        res.status(500).json({ error: 'Failed to add days' });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`API endpoint hidden: ${API_BASE_URL}`);
});
