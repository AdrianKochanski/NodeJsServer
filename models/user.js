const mongoose = require('mongoose');
const bcrypt = require('bcrypt-nodejs');
const Schema = mongoose.Schema;

const userSchema = new Schema({
    email: { type: String, unique: true, lowercase: true, required: true },
    password: { type: String, required: true }
});

userSchema.pre('save', function(next) {

    bcrypt.genSalt(10, (err, salt) => {
        if(err) return next(err);

        bcrypt.hash(this.password, salt, null, (err, hash) => {
            if(err) return next(err);
            
            this.password = hash;
            next();
        })
    })
});

userSchema.methods.comparePassword = (passwordText, passwordEncrypt, callback) => {
    bcrypt.compare(passwordText, passwordEncrypt, (err, isMatch) => {
        console.log(err);
        console.log(isMatch);
        if(err) return callback(err);
        callback(null, isMatch);
    })
};

module.exports = mongoose.model('user', userSchema);
