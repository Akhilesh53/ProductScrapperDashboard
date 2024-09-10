import express from 'express';
import passport from 'passport';
import async from 'async';
import nodemailer from 'nodemailer';
import crypto from 'crypto';
import User from '../models/userSchema.js'
import userSchema from '../models/userSchema.js';

let userRoutes = express.Router();

function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    //console.log('User not authenticated. Pls login first to access this page');
    req.flash('error_msg', 'User not authenticated. Pls login first to access this page');
    res.redirect('/login');
}


//get login
userRoutes.get('/login', (req, res) => {
    res.render('./users/login');
})

// do login
userRoutes.post('/login', passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
    failureFlash: true,
    failureMessage: "Invalid email or password"
}))

// get signup
userRoutes.get('/signup', (req, res) => {
    res.render('./users/signup');
})

// do signup
userRoutes.post('/signup', (req, res) => {
    let { name, email, password } = req.body;

    let userData = {
        name,
        email
    }

    User.register(userData, password, (err, user) => {
        if (err) {
            console.log('Error while user register!', err);
            req.flash('error_msg', 'Error while user register!');
            return res.redirect('/signup');
        }
        req.flash('success_msg', 'User registered successfully!');
        res.redirect('/login');
    })
})

// forget password
userRoutes.get('/forgot', (req, res) => {
    res.render('./users/forgot');
})

// send email to user
userRoutes.post('/forgot', (req, res, next) => {
    let email = req.body.email;

    if (email === '') {
        req.flash('error_msg', 'Email is required');
        return res.redirect('/forgot');
    }

    async.waterfall([
        // Generate token
        (done) => {
            crypto.randomBytes(20, (err, buf) => {
                if (err) {
                    return done(err);
                }
                let token = buf.toString('hex');
                done(null, token);
            });
        },
        // Save the token to the user
        (token, done) => {
            userSchema.findOne({ email: email })
                .then((user) => {
                    if (!user) {
                        req.flash('error_msg', 'No account with that email address exists');
                        return res.redirect('/forgot');
                    }
                    user.resetPasswordToken = token;
                    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
                    return user.save();
                })
                .then((user) => {
                    done(null, token, user);
                })
                .catch((err) => {
                    console.log('Error while finding or saving user:', err);
                    req.flash('error_msg', 'Error processing request');
                    return res.redirect('/forgot');
                });
        },
        // Send email to user
        (token, user, done) => {
            let smtpTransport = nodemailer.createTransport({
                service: 'Gmail',
                auth: {
                    user: process.env.EMAIL,
                    pass: process.env.PASSWORD
                }
            });

            let mailOptions = {
                to: user.email,
                from: 'Product Scrapper <productscrapper@gmail.com>',
                subject: 'Password Recovery - AuProduct Scrapper',
                text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n
                       Please click on the following link, or paste it into your browser to complete the process:\n\n
                       http://${req.headers.host}/reset/${token}\n\n
                       If you did not request this, please ignore this email and your password will remain unchanged.\n`
            };

            smtpTransport.sendMail(mailOptions, (err) => {
                if (err) {
                    console.log('Error sending email:', err);
                    req.flash('error_msg', 'Error sending recovery email');
                    return res.redirect('/forgot');
                }
                req.flash('success_msg', 'An email has been sent to ' + user.email + ' with further instructions.');
                res.redirect('/forgot');
            });
        }
    ], (err) => {
        if (err) {
            console.log('Error in waterfall:', err);
            return next(err);
        }
    });
});

// change password
userRoutes.get('/password/change', isAuthenticated, (req, res) => {
    res.render('./users/changepassword');
});


userRoutes.post('/password/change', (req, res) => {

    if (req.body.password !== req.body.confirmPassword) {
        req.flash('error_msg', 'Passwords do not match');
        return res.redirect('/password/change');
    }

    userSchema.findOne({ email: req.user.email }).then((user) => {
        user.setPassword(req.body.password, (err) => {
            if (err) {
                console.log('Error while setting new password:', err);
                req.flash('error_msg', 'Error while setting new password');
                return res.redirect('/password/change');
            }
            user.save().then(() => { }).catch((err) => {
                console.log('Error while saving user:', err);
                req.flash('error_msg', 'Error while saving user');
                return res.redirect('/password/change');
            });
            req.flash('success_msg', 'Password changed successfully');
            res.redirect('/dashboard');
        });
    })
})

// reset password
userRoutes.get('/reset/:token', (req, res) => {
    res.render('./users/changepassword');
})

userRoutes.post('/reset/:token', (req, res) => {
    async.waterfall([
        // Get the user details from the request
        (done) => {
            let token = req.params.token;
            let password = req.body.password;
            let confirmPassword = req.body.confirmPassword;

            // Check if passwords match
            if (password !== confirmPassword) {
                req.flash('error_msg', 'Passwords do not match');
                return res.redirect(`/reset/${token}`);
            }

            // Find the user by token and ensure the token hasn't expired
            userSchema.findOne({
                resetPasswordToken: token,
                resetPasswordExpires: { $gt: Date.now() }
            }).then((user) => {
                if (!user) {
                    req.flash('error_msg', 'Password reset token is invalid or has expired');
                    return res.redirect('/forgot');
                }

                // Save the new password
                user.password = password; // Assuming hashing is handled in userSchema pre-save hook
                user.resetPasswordToken = undefined;
                user.resetPasswordExpires = undefined;

                user.save()
                    .then(() => {
                        req.logIn(user, (err) => {
                            done(err, user);
                        });
                    })
                    .catch((err) => {
                        console.log('Error while saving user:', err);
                        req.flash('error_msg', 'Error saving the new password');
                        return res.redirect('/forgot');
                    });
            }).catch((err) => {
                console.log('Error while finding user:', err);
                req.flash('error_msg', 'Error processing request');
                return res.redirect('/forgot');
            });
        },
        // Send confirmation email
        (user, done) => {
            let smtpTransport = nodemailer.createTransport({
                service: 'Gmail',
                auth: {
                    user: process.env.GMAIL_EMAIL,
                    pass: process.env.GMAIL_PASSWORD
                }
            });

            let mailOptions = {
                to: user.email,
                from: 'Ghulam Abbas <myapkforest@gmail.com>',
                subject: 'Your password has been changed',
                text: `Hello ${user.name},\n\nThis is confirmation that the password for your account (${user.email}) has been changed.`
            };

            smtpTransport.sendMail(mailOptions, (err) => {
                if (err) {
                    console.log('Error sending confirmation email:', err);
                    req.flash('error_msg', 'Error sending confirmation email');
                    return res.redirect('/forgot');
                }
                req.flash('success_msg', 'Your password has been changed successfully.');
                res.redirect('/login');
                done(null); // Ensure to call `done` to proceed
            });
        }
    ], (err) => {
        if (err) {
            console.log('Error in waterfall:', err);
            req.flash('error_msg', 'Error processing request');
            return res.redirect('/forgot');
        }
    });
});


export default userRoutes;