//jshint esversion:6
//environment vars
require('dotenv').config()
const express = require("express");
const bodyparser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
//const encrypt = require("mongoose-encryption");
//const md5 = require("md5");
//const bcrypt = require("bcrypt");
//const saltRounds = 10;
const session = require('express-session')
const passportLocalMongoose = require("passport-local-mongoose"); //this will use passport local so no need to require passport local.
const passport = require("passport");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate')

const app = express();

app.use(express.static("public"));

app.set('view engine', 'ejs');
app.use(bodyparser.urlencoded({
  extended: true
}));

app.use(session({
  secret: 'Our little secret.',
  resave: false,
  saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());

//mongoose connection setup
mongoose.set('useCreateIndex', true);
mongoose.connect("mongodb://localhost:27017/Userdb", {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId : String,
  secret : String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//userSchema.plugin(encrypt ,{secret : process.env.SECRET , encryptedFields : ['password']});

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo'
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res) {
  res.render("home");
});

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });


app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
      // Successful authentication, redirect home.
    res.redirect('/secrets');
});

app.get('/submit' , function (req,res) {
  if(req.isAuthenticated()){
    res.render("submit");
  }
  else{
    res.redirect("/login");
  }
});

app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/register", function(req, res) {
  res.render("register");
});

app.get("/secrets" , function(req,res){
  User.find({"secret" :{$ne : null}} , function (err, founduser) {
    if(err){
      console.log(err);
    } else{
      if(founduser){
        res.render("secrets" , {userswithsecrets : founduser});
      }
    }
  });
});

app.get('/logout' , function (req,res) {
  req.logout();
  res.redirect("/");
});

app.post("/submit",function(req,res){
  const submittedsecret = req.body.secret;
  console.log(submittedsecret);
  User.findById(req.user._id , function(err,founduser){
    if(err){
      console.log(err);
    } else{
      if(founduser){
        founduser.secret = submittedsecret;
        founduser.save(function (err) {
          if(err){
            console.log(err);
          }else{
            res.redirect("/secrets");
          }
        });
      }
    }
  })
});

app.post('/register', function (req,res) {
  User.register({username : req.body.username} , req.body.password , function(err,user){
    if(err){
      console.log(err);
      res.redirect("/register");
    }
    else{
      passport.authenticate("local")(req,res,function () {
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/login" , function(req,res) {
  const user = new User({
    email : req.body.username,
    password : req.body.password
  });
  req.login(user,function (err) {
    if(err){
      console.log(err);
    } else{
      passport.authenticate("local")(req,res,function () {
        res.redirect("/secrets");
    });
  }

  });
});
//register user request
/*app.post("/register", function(req, res) {
  let username = req.body.username;
  let password = req.body.password;

  bcrypt.hash(password, saltRounds, function(err, hash) {
    // Store hash in your password DB.
    const newuser = new User({
      email: username,
      password: hash
    });
    newuser.save(function(err) {
      if (err) {
        console.log(err);
      } else {
        res.render('secrets');
      }
    });
  });
});*/
//login
/*app.post("/login", function(req, res) {
  let username = req.body.username;
  let password = req.body.password;

  User.findOne({
    email: username
  }, function(err, founduser) {
    if (err) {
      console.log(err);
    } else {
      if (founduser) {
        bcrypt.compare(password, founduser.password, function(err, result) {
          // result == true
          if (result === true) {
            res.render("secrets");
          }
        });
      }
    }
  });
});*/

app.listen(3000, function() {
  console.log("Server started at 3000");
});
