const express = require('express');
const { ensureAuthenticated } = require('./middleware');
const validator = require('validator');
const User = require('../models/User');
const router = express.Router();

router.get('/', ensureAuthenticated, (req, res) => {
    res.render('profile', { user: req.user });
});

router.post('/', ensureAuthenticated, async (req, res) => {
    let { name, email, bio } = req.body;

    if (!validator.isLength(name, { min: 3, max: 50 })) {
        return res.render('profile', { user: req.user, error: 'Name must be 3-50 characters' });
    }
    if (!validator.isEmail(email)) {
        return res.render('profile', { user: req.user, error: 'Invalid email' });
    }
    bio = validator.escape(bio).substring(0, 500);

    await User.findByIdAndUpdate(req.user.id, { name, email, bio });
    req.flash('success_msg', 'Profile updated successfully');
    res.redirect('/dashboard');
});

module.exports = router;
