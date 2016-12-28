var mongoose = require( 'mongoose' );
var crypto = require('crypto'); // To do the setting and the checking of the password we can use Mongoose schema methods – these are essentially functions that you add to the schema. These will both make use of the Node.js crypto module.
var jwt = require('jsonwebtoken');


// There’s a simple user schema defined in /app_api/models/users.js.
// It defines the need for an email address, a name, a hash and a salt
// – the hash and salt will be used instead of saving a password.

// Saving user passwords is a big no-no.
// Should a hacker get a copy of your database you want to make sure that they
// can’t use it to log in to accounts. This is where the hash and salt come in.
// The salt is a string of characters unique to each user. The hash is created
// by combining the password provided by the user and the salt, and then applying
// one-way encryption. As the hash cannot be decrypted, the only way to authenticate
// a user is to take the password, combine it with the salt and encrypt it again.
// If the output of this matches the hash, then the password must have been correct.
var userSchema = new mongoose.Schema({
  email: {
    type: String,
    unique: true, //The email is set to unique as we’ll use it for the login credentials.
    required: true
  },
  name: {
    type: String,
    required: true
  },
  hash: String,
  salt: String
});

// To save the reference to the password we can create a new method called setPassword on
// the userSchema schema that accepts a password parameter.
// The method will then use crypto.randomBytes to set the salt, and crypto.pbkdf2Sync to set the hash.
// We’ll use this method when creating a user;
// instead of saving the password to a password path we will be able to pass it to
// the setPassword function to set the salt and hash paths in the user document.
userSchema.methods.setPassword = function(password){
  this.salt = crypto.randomBytes(16).toString('hex');
  this.hash = crypto.pbkdf2Sync(password, this.salt, 1000, 64).toString('hex');
};

// Checking the password is a similar process, but we already have the salt from
// the Mongoose model. This time we just want to encrypt the salt and the password
// and see if the output matches the stored hash.
userSchema.methods.validPassword = function(password) {
  var hash = crypto.pbkdf2Sync(password, this.salt, 1000, 64).toString('hex');
  return this.hash === hash;
};


// This module exposes a sign method that we can use to create a JWT, simply
// passing it the data we want to include in the token, plus a secret that the
// hashing algorithm will use. The data should be sent as a JavaScript object,
// and include an expiry date in an exp property.
// Returns a JWT.
userSchema.methods.generateJwt = function() {
  var expiry = new Date();
  expiry.setDate(expiry.getDate() + 7);

  return jwt.sign({
    _id: this._id,
    email: this.email,
    name: this.name,
    exp: parseInt(expiry.getTime() / 1000),
  }, "MY_SECRET"); // DO NOT KEEP YOUR SECRET IN THE CODE!
};

mongoose.model('User', userSchema);
