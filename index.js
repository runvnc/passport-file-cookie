var fs = require('fs');
var crypto = require('crypto');
var bcrypt = require('bcryptjs');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;                 
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var cookieSession = require('cookie-session');
var randomstring = require('randomstring');

var configPath = process.env.HOME + '/.pass-fs-cookie';

passport.use(new LocalStrategy(
  function(username, password, callback) {
    getHash(username, function(hash) {
      bcrypt.compare(password, hash, function(err, res) {
        if(err) {
          callback(err);
        } else if(res) {
          callback(null, {user:username});
        } else {
          callback(null, false, { message: 'Wrong password' });
        }
      });
    });
  }
));

var userCache = {};

passport.serializeUser(function(user, callback) {
  fs.writeFileSync(configPath+"/"+user.user, JSON.stringify(user));
  userCache[user.user] = user;
  callback(null, user.user);
});

passport.deserializeUser(function(id, callback) {
  if (userCache.hasOwnProperty(id)) {
    callback(userCache[id]);
  } else {
    var userData = fs.readFileSync(configPath+"/"+id, 'utf8');
    var user = JSON.parse(userData);
    userCache[id] = user;
    callback(null, user);
  }
});

var setPassword = function(user, password) {
  var salt = bcrypt.genSaltSync(10);
  var hash = bcrypt.hashSync(password, salt);
  fs.writeFileSync(configPath+"/"+user, hash);
}

getHash = function(user, cb) {
  cb(fs.readFileSync(configPath+"/"+user, 'utf8'));  
}

readConfig = function(cb) {
  var fname = configPath+'/config.json';  
  fs.exists(fname, function(exists) {
    if (exists) {
      fs.readFile(fname, 'utf8', function (err, data) {
        if (err) throw err;
        var conf = JSON.parse(data);
        cb(conf);
      });
    } else {
      var data = {
        cookieSecret: crypto.randomBytes(64).toString(),
        cookieParserRandom: randomstring.generate()
      };
      fs.writeFile(fname, JSON.stringify(data), function (err) {
        if (err) throw err;
        cb(data);
      });
    }
}

module.exports.setupAppServer = function(app, callback) {
  readConfig(function(config) {
    app.use(cookieParser(config.cookieParserRandom));
    app.use(cookieSession({
      secret: config.cookieSecret,
      maxage: 1000 * 60 * 60 * 24 * 7,
      signed: true
    }));
    app.use(bodyParser.urlencoded({ extended: false }))
    app.use(passport.initialize());
    app.use(passport.session());

    app.use(flash());
    app.use(function (req, res, next) {
      if (req.url === '/login' || req.isAuthenticated()) {
        return next();
      } else {
        res.redirect("/login");
      }
    });

    callback();
  });
};

