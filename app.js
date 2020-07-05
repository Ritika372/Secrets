//jshint esversion:6
require('dotenv').config()
const express = require("express");
const bodyparser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");

const app = express();

app.use(express.static("public"));

app.set('view engine' ,'ejs');
app.use(bodyparser.urlencoded({extended : true}));
//mongoose connection setup
mongoose.connect("mongodb://localhost:27017/Userdb" , {useNewUrlParser : true, useUnifiedTopology : true});

const userSchema = new mongoose.Schema({
  email : String,
  password : String
});


userSchema.plugin(encrypt ,{secret : process.env.SECRET , encryptedFields : ['password']});

const User = mongoose.model("User" , userSchema);

app.get("/" , function (req,res) {
  res.render("home");
});

app.get("/login" , function (req,res) {
  res.render("login");
});

app.get("/register" , function (req,res) {
  res.render("register");
});

//register user request
app.post("/register" , function (req,res) {
  let username = req.body.username;
  let password = req.body.password;

  const newuser = new User({
    email : username,
    password : password
  });
  newuser.save(function (err) {
    if(err)
    {
      console.log(err);
    }
    else{
      res.render('secrets');
    }

  });
});
//login
app.post("/login" , function (req,res) {
  let username = req.body.username;
  let password = req.body.password;
  User.findOne({email : username} , function (err, founduser) {
    if(err){
      console.log(err);
    }
    else{
      if(founduser){
        if(founduser.password === password){
          res.render("secrets");
        }

      }
    }
  })
});
app.listen(3000, function () {
  console.log("Server started at 3000");
});
