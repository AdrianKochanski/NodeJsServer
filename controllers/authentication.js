const jwt = require('jwt-simple');
const config = require('../config');
const Users = require("../models/user");

function getJwtToken(user) {
    return {
        token: jwt.encode({
                sub: user.id,
                ait: new Date().getTime()
            }, config.secret
        )
    };
}

exports.signup = function(req, res, next) {
    const {email, password} = req.body;
    if(!email || !password) return res.status(422).send("You must provide email and password");

    Users.findOne({email: email}, function(err, searchedUser){
        if(err) return next(err);
        if(searchedUser) return res.status(422).send("Email already used");

        const user = new Users({
            email: email,
            password: password
        });

        user.save(function(err) {
            if(err) return next(err);
            res.json(getJwtToken(user));
        });
    });
}

exports.signin = function(req, res, next) {
    res.json(getJwtToken(req.user));
}