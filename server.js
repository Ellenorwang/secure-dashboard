const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const path = require('path');
const crypto = require('crypto');
const { body, validationResult } = require('express-validator');
const helmet = require('helmet');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const User = require('./models/User');

const app = express();
const PORT = 3001;
const ENCRYPTION_KEY = crypto.scryptSync("secret-passphrase", 'salt', 32);
const IV = Buffer.alloc(16, 0);

mongoose.connect('mongodb://localhost:27017/secure-dashboard', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 5000
}).then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// =========================
// Security Middleware
// =========================
app.use(helmet());                       
app.disable('x-powered-by');            
app.use(cookieParser());                 
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// =========================
// Session Config
// =========================
app.use(session({
    secret: 'secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: false,                  
        sameSite: 'strict'            
    }
}));

// =========================
// CSRF Protection
// =========================
app.use(csrf({ cookie: true }));
app.use((req, res, next) => {
    res.locals.csrfToken = req.csrfToken(); // 所有视图中可使用 <%= csrfToken %>
    next();
});

// =========================
// Passport Config
// =========================
app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
    try {
        const user = await User.findOne({ email });
        if (!user) return done(null, false, { message: 'User not found' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return done(null, false, { message: 'Incorrect password' });

        return done(null, user);
    } catch (err) {
        return done(err);
    }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err);
    }
});

// =========================
// Encryption Helpers
// =========================
function encrypt(text) {
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, IV);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

function decrypt(text) {
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, IV);
    let decrypted = decipher.update(text, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// =========================
// Routes
// =========================
app.get('/', (req, res) => res.redirect('/login'));

// Login/Register Pages
app.get('/login', (req, res) => res.render('login'));
app.get('/register', (req, res) => res.render('register'));

// Dashboard
app.get('/dashboard', isAuthenticated, (req, res) => {
    let decryptedBio = req.user.bio ? decrypt(req.user.bio) : "";
    res.render('dashboard', { user: { ...req.user.toObject(), bio: decryptedBio } });
});

// Profile Edit Page
app.get('/profile', isAuthenticated, (req, res) => {
    let decryptedBio = req.user.bio ? decrypt(req.user.bio) : "";
    res.render('profile', { user: { ...req.user.toObject(), bio: decryptedBio }, errors: [] });
});

// Register POST
app.post('/register', (req, res) => {
    const { email, password } = req.body;
    User.findOne({ email }).then(async (user) => {
        if (user) return res.redirect('/register');
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ email, password: hashedPassword });
        await newUser.save();

        req.login(newUser, (err) => {
            if (err) throw err;
            return res.redirect('/dashboard');
        });
    }).catch(err => {
        console.error("Registration Error:", err);
        res.redirect('/register');
    });
});

// Login POST
app.post('/login', (req, res, next) => {
    passport.authenticate('local', (err, user) => {
        if (err) return next(err);
        if (!user) return res.redirect('/login');
        req.logIn(user, (err) => {
            if (err) return next(err);
            return res.redirect('/dashboard');
        });
    })(req, res, next);
});

// Profile Update POST
app.post('/profile',
    isAuthenticated,
    [
        body('name').trim().isAlpha('en-US', { ignore: ' ' }).isLength({ min: 3, max: 50 }),
        body('email').isEmail(),
        body('bio').isLength({ max: 500 }).matches(/^[a-zA-Z0-9\s.,!?'-]*$/)
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.render('profile', { user: req.user, errors: errors.array() });
        }

        try {
            const { name, email, bio } = req.body;
            req.user.name = name;
            req.user.email = email;
            req.user.bio = encrypt(bio);
            await req.user.save();

            res.redirect('/dashboard');
        } catch (err) {
            console.error("Profile Update Error:", err);
            res.redirect('/profile');
        }
    }
);

// Logout
app.get('/logout', (req, res, next) => {
    req.logout(function (err) {
        if (err) return next(err);
        res.redirect('/login');
    });
});

// Middleware to check auth
function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect('/login');
}

// Start server
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
