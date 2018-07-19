# passport-cas

[Passport](http://passportjs.org/) authentication strategy using a Central
Authentication Strategy ([CAS](https://wiki.jasig.org/display/CAS/Home)) server.
Supports CAS protocol versions 1.0, 2.0 and 3.0.

```
npm install @rula/passport-cas
```

### Configure Strategy

Minimum configuration requires the CAS url and service parameters to be defined.

```
passport.use(new (require('passport-cas').Strategy) ({
  casUrl: 'http://cas.example.com',
  serviveUrl: `http://localhost:3000'
}, function(req, user, done) {
  User.findOne({username: user.username}, function(err, user) {
    if (err) {
      return done(err);
    }
    if (!user) {
      return done(null, false, {message: "Unknown user'});
    }
    return done(null, user);
  });
}));
```

### Authenticate Requests

Using the Express Passport middleware as an example:

```
exports.casLogin = function(req, res, next) {
  passport.authenticate('cas', function (err, user, info) {
    if (err) {
      return next(err);
    }

    if (!user) {
      req.session.messages = info.message;
      return res.redirect('/');
    }

    req.logIn(user, function (err) {
      if (err) {
        return next(err);
      }

      req.session.messages = '';
      return res.redirect('/');
    });
  })(req, res, next);
};
```