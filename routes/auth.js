const express = require('express');
const bcrypt = require('bcryptjs');
const passport = require('passport');
const User = require('../models/User');
const router = express.Router();

// Login Page
router.get('/login', (req, res) => res.render('login'));

// Register Page
router.get('/register', (req, res) => res.render('register'));

// Register Handle
router.post('/register', async (req, res) => {
    const { name, email, password } = req.body;
    let errors = [];

    if (!name || !email || !password) errors.push({ msg: 'Please fill in all fields' });
    if (password.length < 6) errors.push({ msg: 'Password must be at least 6 characters' });

    if (errors.length > 0) {
        return res.render('register', { errors, name, email });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
        errors.push({ msg: 'Email already registered' });
        return res.render('register', { errors, name, email });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();

    req.flash('success_msg', 'You are now registered and can log in');
    res.redirect('/login');
});

// Login Handle
router.post('/login', passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
    failureFlash: true
}));

// Logout
router.get('/logout', (req, res) => {
    req.logout(() => {
        req.flash('success_msg', 'You are logged out');
        res.redirect('/login');
    });
});

module.exports = router;
