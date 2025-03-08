require('dotenv').config(); // Load environment variables
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const multer = require('multer'); // For handling file uploads
const app = express();
const port = process.env.PORT || 3000;
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const nodemailer = require('nodemailer');
const crypto = require('crypto');


// Use session middleware BEFORE Passport
app.use(session({
    secret: '1105cb3457b81b1ce28f74da8e9507fb5065cffbf0f2be45711a962f0b11138a86cd4915d202d9692bab4a8a3e744df17ae8af6bdb7a5b7f686aa98a7fb40e8f',  // Change this to a strong secret key
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session()); // Enable session support for Passport

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'unknownplayers0007@gmail.com',
        pass: 'rktg zaeq cssg unkf' // Use App Password, not your real Gmail password
    }
});

let otpStorage = {}; // Temporary storage for OTPs


const GitHubStrategy = require('passport-github2').Strategy;

// GitHub OAuth Credentials
const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const GITHUB_CALLBACK_URL = process.env.GITHUB_CALLBACK_URL;

// GitHub OAuth Strategy
passport.use(new GitHubStrategy({
    clientID: GITHUB_CLIENT_ID,
    clientSecret: GITHUB_CLIENT_SECRET,
    callbackURL: GITHUB_CALLBACK_URL
}, async (accessToken, refreshToken, profile, done) => {
    let users = readUserData();
    let user = users.find(u => u.githubId === profile.id);

    if (!user) {
        user = {
            username: profile.username || profile.displayName,
            email: profile.emails ? profile.emails[0].value : null, // Some GitHub users have no public email
            githubId: profile.id,
            profilePhoto: profile.photos[0].value || "/default-avatar.png"
        };
        users.push(user);
        writeUserData(users);
    }

    return done(null, user);
}));

// GitHub Login Routes
app.get('/auth/github', passport.authenticate('github', { scope: ['user:email'] }));

app.get('/auth/github/callback',
    passport.authenticate('github', { failureRedirect: '/login' }),
    (req, res) => {
        req.session.user = req.user;
        res.redirect('/chat');
    }
);

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL;

passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: GOOGLE_CALLBACK_URL  // Ensure this matches the Google Cloud redirect URI
}, async (accessToken, refreshToken, profile, done) => {
    let users = readUserData();
    let user = users.find(u => u.email === profile.emails[0].value);

    if (!user) {
        user = {
            username: profile.displayName,
            email: profile.emails[0].value,
            googleId: profile.id,
            profilePhoto: profile.photos[0].value
        };
        users.push(user);
        writeUserData(users);
    }

    return done(null, user);
}));
passport.serializeUser((user, done) => {
    done(null, user.email);
});

passport.deserializeUser((email, done) => {
    const users = readUserData();
    const user = users.find(u => u.email === email);
    done(null, user);
});

app.use(passport.initialize());
app.use(passport.session());

app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login' }),
    (req, res) => {
        req.session.user = req.user;
        res.redirect('/chat');
    }
);


// Set up multer for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = path.join(__dirname, 'public', 'uploads');
        // Create directory if it doesn't exist
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname);
        cb(null, file.fieldname + '-' + uniqueSuffix + ext);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // Limit file size to 5MB
    fileFilter: function (req, file, cb) {
        // Accept only image files
        if (!file.originalname.match(/\.(jpg|jpeg|png|gif)$/)) {
            return cb(new Error('Only image files are allowed!'), false);
        }
        cb(null, true);
    }
});

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
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));
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

    if (users.some(u => u.email === email)) {
        return res.json({ success: false, message: 'Email already registered' });
    }

    // Generate a 6-digit OTP
    const otp = crypto.randomInt(100000, 999999).toString();
    otpStorage[email] = { otp, expires: Date.now() + 10 * 60000 }; // Valid for 5 minutes

    // Send OTP via email
    try {
        await transporter.sendMail({
            from: 'VedaAI',
            to: email,
            subject: 'Your OTP Code For VedaAI',
            text: `Your OTP code for registering to VedaAI is: ${otp}. It expires in 10 minutes.`,
        });

        res.json({ success: true, message: 'OTP sent to email. Please verify.' });
    } catch (error) {
        console.error("Error sending email:", error);
        res.json({ success: false, message: 'Error sending OTP' });
    }
});

app.post('/api/verify-otp', async (req, res) => {
    const { username, email, password, otp } = req.body;

    // Check if OTP is valid
    if (!otpStorage[email] || otpStorage[email].otp !== otp || Date.now() > otpStorage[email].expires) {
        return res.json({ success: false, message: 'Invalid or expired OTP' });
    }

    delete otpStorage[email]; // Remove OTP after verification

    // Hash password and save user
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = { username, email, profilePhoto: '/default-avatar.png', password: hashedPassword };
    const users = readUserData();
    users.push(user);
    writeUserData(users);
    
    res.json({ success: true, message: 'Registration complete! You can now log in.' });
});


// Add profile photo upload endpoint
app.post('/api/upload-profile-photo', isAuthenticated, upload.single('profilePhoto'), (req, res) => {
    try {
        if (!req.file) {
            return res.json({ success: false, message: 'No file uploaded' });
        }

        const users = readUserData();
        const userIndex = users.findIndex(u => u.username === req.session.user.username);
        
        if (userIndex === -1) {
            return res.json({ success: false, message: 'User not found' });
        }

        // Get relative path for storing in JSON
        const relativePath = '/uploads/' + path.basename(req.file.path);
        
        // Update user data with profile photo path
        users[userIndex].profilePhoto = relativePath;
        writeUserData(users);
        
        // Update session user data
        req.session.user.profilePhoto = relativePath;
        
        res.json({ 
            success: true, 
            message: 'Profile photo uploaded successfully',
            profilePhoto: relativePath
        });
    } catch (error) {
        console.error('Error uploading profile photo:', error);
        res.json({ success: false, message: 'Error uploading profile photo' });
    }
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

// Add endpoint to get user profile info
app.get('/api/user-profile', isAuthenticated, (req, res) => {
    res.json({
        username: req.session.user.username,
        email: req.session.user.email,
        profilePhoto: req.session.user.profilePhoto || '/default-avatar.png'
    });
});

// Handle chat messages
app.post('/api/message', async (req, res) => {
    const userMessage = req.body.message;
    if (userMessage === "wtb" || userMessage.includes("what is wtb") || userMessage.includes("what is weak towards bottom")) {
        return res.json({ reply: "<b>WTB or Weak Towards Bottom</b> is the second highest percentage in Volume or OI ,which should be more than 75% at the bottom which shows Bearish Pressure naturally(Not Shifted).<br>It is Indicated by yellow color." });
    }
    if (userMessage === "wtt" || userMessage.includes("what is wtt") || userMessage.includes("what is weak towards top")) {
        return res.json({ reply: "<b>WTT or Weak Towards Top</b> is the second highest percentage in Volume or OI ,which should be more than 75% at the top side which shows Bullish Pressure naturally(Not Shifted).<br>It is Indicated by yellow color." });
    }
    if (userMessage === "strong" || userMessage.includes("what is strong") || userMessage.includes("what is strong in ltp calculator") ) {
        return res.json({ reply: "When the <b>Second highest percentage</b> is not Bigger than 75% of the highest percentage the condition show that ,we can get a good reversal(expected) from there, this refers <strong><b>Strong</strong></b>" });
    }
    if (userMessage === "volume" || userMessage.includes("what is volume") || userMessage.includes("what is volume in ltp calculator") ) {
        return res.json({ reply: "<b>Volume</b> in the stock market is the number of lots traded during a specific period of time. It is not decreased whole day and starts from zero another day, it helps to detemine the market" });
    }
    if (userMessage === "oi" || userMessage.includes("what is oi") || userMessage.includes("what is oi in ltp calculator") ) {
        return res.json({ reply: "<b>OI</b> in the stock market is the number of lots active on a strike price. It is continued whole week and expire at the <b>Symbol's Expiry</b> and it is used to determine support and resitance" });
    }
    if (userMessage === "support" || userMessage.includes("what is support") || userMessage.includes("what is support in ltp calculator") ) {
        return res.json({ reply: "Seeing to the pair of imaginary line, from the one <b>In The Money</b> to the <b>Out The Money</b> ,the highest OI or Volume near to the imaginary line in the put side is considered as <b>Support</b>" });
    }
    if (userMessage === "resistance" || userMessage.includes("what is resistance") || userMessage.includes("what is resistance in ltp calculator") ) {
        return res.json({ reply: "Seeing to the pair of imaginary line, from the one <b>In The Money</b> to the <b>Out The Money</b> ,the highest OI or Volume near to the imaginary line in the call side is considered as <b>Resistance</b>" });
    }
    if (userMessage === "reversal" || userMessage.includes("what is reversal") || userMessage.includes("what is reversal in ltp calculator") ) {
        return res.json({ reply: "When there is a specific place that we know that the market will reverse from there the thing is reffered as <b>Reversal</b>" });
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