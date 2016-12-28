// Passport is a Node module that simplifies the process of handling authentication
// in Express. It provides a common gateway to work with many different authentication
// “strategies”, such as logging in with Facebook, Twitter or Oauth. The strategy
// we’ll use is called “local”, as it uses a username and password stored locally.
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var mongoose = require('mongoose');
var User = mongoose.model('User');

// For a local strategy we essentially just need to write a Mongoose query on the
// User model. This query should find a user with the email address specified, and
// then call the validPassword method to see if the hashes match. Pretty simple.

//There’s just one curiosity of Passport to deal with. Internally the local strategy
// for Passport expects two pieces of data called username and password. However
// we’re using email as our unique identifier, not username. This can be configured
// in an options object with a usernameField property in the strategy definition.
// After that, it’s over to the Mongoose query.
passport.use(new LocalStrategy({
    usernameField: 'email'
  },
  function(username, password, done) {
    User.findOne({ email: username }, function (err, user) {
      if (err) { return done(err); }
      // Return if user not found in database
      if (!user) {
        return done(null, false, {
          message: 'User not found'
        });
      }
      // Return if password is wrong
      if (!user.validPassword(password)) { // Note how the validPassword schema method is called directly on the user instance.
        return done(null, false, {
          message: 'Password is wrong'
        });
      }
      // If credentials are correct, return the user object
      return done(null, user);
    });
  }
));
