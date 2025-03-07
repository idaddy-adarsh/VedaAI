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
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const app = express();
const port = process.env.PORT || 3000;

// Google OAuth Configuration
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const CALLBACK_URL = 'https://vedaai.onrender.com/auth/google/callback';

// Set up passport for Google OAuth
passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: CALLBACK_URL,
    passReqToCallback: true
  },
  function(req, accessToken, refreshToken, profile, done) {
    // Check if user exists in our system
    const users = readUserData();
    let user = users.find(u => u.googleId === profile.id);
    
    if (!user) {
      // Create new user with Google profile
      const newUser = {
        googleId: profile.id,
        username: profile.displayName,
        email: profile.emails && profile.emails[0] ? profile.emails[0].value : '',
        profilePhoto: profile.photos && profile.photos[0] ? profile.photos[0].value : '/default-avatar.png'
      };
      
      users.push(newUser);
      writeUserData(users);
      user = newUser;
    }
    
    return done(null, user);
  }
));

// Serialize user ID for session
passport.serializeUser((user, done) => {
  done(null, user.googleId || user.username);
});

// Deserialize user from session
passport.deserializeUser((id, done) => {
  const users = readUserData();
  const user = users.find(u => u.googleId === id || u.username === id);
  done(null, user);
});

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
    secret: process.env.SESSION_SECRET || 'secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Initialize Passport and restore authentication state from session
app.use(passport.initialize());
app.use(passport.session());

const userFilePath = path.join(__dirname, 'user.json');

// Ensure user.json exists
if (!fs.existsSync(userFilePath)) {
    fs.writeFileSync(userFilePath, JSON.stringify([]));
}

function readUserData() {
    try {
        const data = fs.readFileSync(userFilePath, 'utf-8');
        return JSON.parse(data);
    } catch (error) {
        console.error('Error reading user data:', error);
        return [];
    }
}

function writeUserData(users) {
    fs.writeFileSync(userFilePath, JSON.stringify(users, null, 2));
}

// Google Auth Routes
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect to chat
    res.redirect('/chat');
  });

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const users = readUserData();
    const user = users.find(u => u.username === username);

    if (user && user.password && await bcrypt.compare(password, user.password)) {
        req.login(user, function(err) {
            if (err) { return res.json({ success: false, message: 'Authentication failed' }); }
            return res.json({ success: true });
        });
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

    const user = { 
        username, 
        email, 
        password: hashedPassword,
        profilePhoto: '/default-avatar.png' // Default profile photo
    };
    users.push(user);
    writeUserData(users);
    res.json({ success: true });
});

// Logout route
app.get('/logout', (req, res) => {
    req.logout(function(err) {
        if (err) { return next(err); }
        res.redirect('/login');
    });
});

// Add profile photo upload endpoint
app.post('/api/upload-profile-photo', isAuthenticated, upload.single('profilePhoto'), (req, res) => {
    try {
        if (!req.file) {
            return res.json({ success: false, message: 'No file uploaded' });
        }

        const users = readUserData();
        const userIndex = users.findIndex(u => (u.googleId && u.googleId === req.user.googleId) || 
                                             (!u.googleId && u.username === req.user.username));
        
        if (userIndex === -1) {
            return res.json({ success: false, message: 'User not found' });
        }

        // Get relative path for storing in JSON
        const relativePath = '/uploads/' + path.basename(req.file.path);
        
        // Update user data with profile photo path
        users[userIndex].profilePhoto = relativePath;
        writeUserData(users);
        
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
    if (req.isAuthenticated()) {
        return next();
    } else {
        res.redirect('/login');
    }
}

app.get('/', (req, res) => {
    if (req.isAuthenticated()) {
        res.redirect('/chat');
    } else {
        res.redirect('/login');
    }
});

app.get('/home', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/chat', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'chatbot.html'));
});

// Add endpoint to get user profile info
app.get('/api/user-profile', isAuthenticated, (req, res) => {
    res.json({
        username: req.user.username,
        email: req.user.email,
        profilePhoto: req.user.profilePhoto || '/default-avatar.png'
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

// Ensuring all routes are handled before the 404
app.use((req, res) => {
    res.status(404).send('Page not found');
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});