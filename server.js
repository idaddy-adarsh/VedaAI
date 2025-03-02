require('dotenv').config(); // Load environment variables
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const app = express();
const port = 3000;

app.use(bodyParser.json());
app.use(express.static('public'));
app.use(session({
    secret: 'secret-key',
    resave: false,
    saveUninitialized: false
}));

const userFilePath = path.join(__dirname, 'user.json');

function readUserData() {
    const data = fs.readFileSync(userFilePath, 'utf-8');
    return JSON.parse(data);
}

function writeUserData(users) {
    fs.writeFileSync(userFilePath, JSON.stringify(users, null, 2));
}

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const users = readUserData();
    const user = users.find(u => u.username === username);

    if (user && await bcrypt.compare(password, user.password)) {
        req.session.user = user;
        res.json({ success: true });
    } else {
        res.json({ success: false, message: 'Invalid credentials' });
    }
});

app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    const users = readUserData();

    if (users.some(u => u.username === username || u.email === email)) {
        return res.json({ success: false, message: 'Username or email already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = { username, email, password: hashedPassword };
    users.push(user);
    writeUserData(users);
    res.json({ success: true });
});

function isAuthenticated(req, res, next) {
    if (req.session.user) {
        return next();
    } else {
        res.redirect('/login');
    }
}

app.get('/home', (req, res) => {
    res.sendFile(__dirname + '/public/index.html');
});

app.get('/login', (req, res) => {
    res.sendFile(__dirname + '/public/login.html');
});

app.get('/register', (req, res) => {
    res.sendFile(__dirname + '/public/register.html');
});

app.get('/chat', isAuthenticated, (req, res) => {
    res.sendFile(__dirname + '/public/chatbot.html');
});

// Load API key from environment variables
const API_KEY = process.env.GEMINI_API_KEY;

// Handle chat messages
app.post('/api/message', async (req, res) => {
    const userMessage = req.body.message.toLowerCase();

    // Custom response for "who are you?"
    if (userMessage.includes("who are you")) {
        return res.json({ reply: "I'm VedaAI, your intelligent chatbot assistant!" });
    }

    try {
        const response = await axios.post(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${API_KEY}`, {
            contents: [
                {
                    parts: [{ text: userMessage }]
                }
            ]
        });

        let reply = response.data?.candidates?.[0]?.content?.parts?.[0]?.text || "Sorry, I couldn't understand that.";

        // Detect if the response is code (basic check for code syntax like functions, classes, etc.)
        if (/(```|function |class |const |let |var |#include |<\?php)/.test(reply)) {
            reply = `<pre><code>${reply}</code></pre>`;
        } else {
            // Format bold text if **text** pattern is found
            reply = reply.replace(/\*\*(.*?)\*\*/g, "<b>$1</b>");
        }

        res.json({ reply });
    } catch (error) {
        console.error('Error connecting to Gemini API:', error.response?.data || error.message);
        res.status(500).json({ reply: 'Sorry, something went wrong. Please try again later.' });
    }
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
