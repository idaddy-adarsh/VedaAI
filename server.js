require('dotenv').config(); // Load environment variables
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const app = express();
const port = 3000;

const apiKey = process.env.GEMINI_API_KEY;
const genAI = new GoogleGenerativeAI(apiKey);

const model = genAI.getGenerativeModel({
    model: "gemini-2.0-flash",
    systemInstruction: "You are Veda AI, an intelligent chatbot from India designed to help in trading in the Indian stock market and for general use."
});

const generationConfig = {
    temperature: 1,
    topP: 0.95,
    topK: 40,
    maxOutputTokens: 8192,
    responseMimeType: "text/plain",
};

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

// Handle chat messages
app.post('/api/message', async (req, res) => {
    const userMessage = req.body.message;
    if (userMessage === "wtb" || userMessage.includes("what is wtb") || userMessage.includes("what is weak towards bottom")) {
        return res.json({ reply: "<b>WTB or Weak Towards Bottom</b> is the second highest percentage in Volume or OI ,which should be more than 75% at the bottom which shows Bearish Pressure naturally(Not Shifted).<br>It is Indicated by yellow color." });
    }
    if (userMessage === "wtt" || userMessage.includes("what is wtt") || userMessage.includes("what is weak towards top")) {
        return res.json({ reply: "<b>WTB or Weak Towards Top</b> is the second highest percentage in Volume or OI ,which should be more than 75% at the top side which shows Bullish Pressure naturally(Not Shifted).<br>It is Indicated by yellow color." });
    }
    if (userMessage === "strong" || userMessage.includes("what is strong") || userMessage.includes("what is strong in ltp calculator") ) {
        return res.json({ reply: "When the <b>Second highest percentage</b> is not Bigger than 75% of the highest percentage the condition show that ,we can get a good reversal(expected) from there, this refers <strong><b>Strong</strong></b>" });
    }
    if (userMessage === "volume" || userMessage.includes("what is volume") || userMessage.includes("what is volume in ltp calculator") ) {
        return res.json({ reply: "<b>Volume</b> in the stock market is the number of shares traded during a specific period of time.It is not decreased whole day and starts from zero another day, it helps to detemine the market" });
    }
    try {
        const chatSession = model.startChat({
            generationConfig,
            history: [],
        });

        const result = await chatSession.sendMessage(userMessage);
        let reply = result.response.text();

        // Detect if the response is code
        if (/(```|function |class |const |let |var |#include |<\?php)/.test(reply)) {
            reply = reply.replace(/```/g, ""); // Remove triple backticks if they exist
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
