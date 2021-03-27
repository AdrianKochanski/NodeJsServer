const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const passportJwt = require('passport-jwt');
const LocalStrategy = require('passport-local');

const jwtExtract = passportJwt.ExtractJwt;
const jwtStrategy = passportJwt.Strategy;

const localLogin = new LocalStrategy({
    usernameField: 'email'
}, function(email, password, done) {
    User.findOne({email: email}, (err, user) => {
        if(err) return done(err, false);
        if(!user) return done(null, false)
        else user.comparePassword(password, user.password, (err, isMatch) => {
            if(err) return done(err, false);
            if(!isMatch) return done(null, false);
            else return done(null, user);
        });
    })
});

const jwtLogin = new jwtStrategy({
    jwtFromRequest: jwtExtract.fromHeader('authorization'),
    secretOrKey: config.secret
}, (payload, done) => {
    User.findById(payload.sub, (err, user) => {
        if(err) return done(err, false);
        if(user) return done (null, user)
        else return done(null, false);
    });
});

passport.use(jwtLogin);
passport.use(localLogin);