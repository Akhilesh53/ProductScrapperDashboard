import express from 'express';
import bodyParser from 'body-parser';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import passport from 'passport';
import session from 'express-session';
import { Strategy as LocalStrategy } from 'passport-local';
import flash from 'connect-flash';
import User from './models/userSchema.js';

import userRoutes from './routes/user.routes.js';

dotenv.config();
const port = process.env.PORT || 3000;

const app = express();

mongoose.connect(process.env.MONGO_URI, {
    autoCreate: true,
    autoIndex: true,
}).then(() => {
    console.log('Database connected');
}).catch((err) => {
    console.log('Database connection error', err)
    process.exit(1);
})

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: true,
    saveUninitialized: true,
}))

app.use(passport.initialize())
app.use(passport.session())

passport.use(new LocalStrategy({ usernameField: 'email' }, User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.use(flash());

//set flasg global mssgs
app.use((req, res, next) => {
    res.locals.error_msg = req.flash('error_msg');
    res.locals.success_msg = req.flash('success_msg');
    res.locals.error = req.flash(('error'));
    res.locals.currentUser = req.user;
    next();
})

app.set('view engine', 'ejs');
app.set('views', './views');
app.set(express.static('public'))

app.use(userRoutes)

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
})

