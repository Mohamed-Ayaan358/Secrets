require('dotenv').config()
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const encrypt = require('mongoose-encryption');
const md5 = require('md5')
const bcrypt = require('bcrypt');
const saltRounds = 10;
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

//Uses Session , initialize passport, and connect to the session
app.use(session({
    secret:"Our little secret.",
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());


mongoose.connect("mongodb://localhost:27017/secrets", { useNewUrlParser: true });
const userschema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String,
});

userschema.plugin(passportLocalMongoose);
userschema.plugin(findOrCreate);

// userschema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });
const User = new mongoose.model("User", userschema);
//Mongoose decrypts and encrypts by itself

//To set up the google Auth0 strategy
passport.use(User.createStrategy());
//From passport-local-mongoose for local
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());


//From passport-google-oauth20 for google and local

passport.serializeUser(function(user,done){
    done(null,user.id);
})
passport.deserializeUser(function(id,done){
    User.findById(id,function(err,user){
        done(err,user);
    });
});
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));



app.get('/', function (req, res) {

    res.render("home");
});
app.get('/auth/google',function(req,res){
    passport.authenticate('google', { scope: ["profile"] })(req, res);
});
app.get('/auth/google/secrets',
    passport.authenticate("google",{failureRedirect:'/login'}),function(req,res){
        res.redirect("/secrets");
});
app.get('/login', function (req, res) {
    res.render("login");
})
app.get('/register', function (req, res) {
    res.render("register");
})
app.get("/logout", function (req, res) {
    res.render("home");
})
app.get("/secrets", function (req, res) {
    //To keep it valid for the session
    // if(req.isAuthenticated()){
    //     res.render("secrets");
    // }else{
    //     res.redirect("/login");
    // }
    //Checks that secret is not null
    User.find({"secret":{$ne: null}},function(err,foundUsers){
        if(err){
            console.log(err);
        }else{
            if(foundUsers){
                res.render("secrets",{usersWithSecrets:foundUsers});
            }
        }
    });
})

app.get('/submit',function(req,res){
    
    if(req.isAuthenticated()){
        res.render("submit");
    }else{
        res.redirect("/login");
    }

    
});
app.post('/submit',function(req,res){
    const submittedSecret = req.body.secret;
    
    User.findById(req.user.id,function(err,foundUser){
        if(err){
            console.log(err);
        }else{
            if(foundUser){
                foundUser.secret = submittedSecret;
                foundUser.save(function(){
                    res.redirect("/secrets");
                });
            }
        }
    });
});

//Using normal hashing
// app.post("/register", function (req, res) {
//     const newuser = new User({
//         email: req.body.username,
//         password: md5(req.body.password)
//     });
//     newuser.save(function (err) {
//         if (!err) {
//             //Rendered here to attain some security
//             res.render("secrets");
//         }
//     });
// });
// app.post("/login", function (req, res) {
//     const username = req.body.username;
//     const password = md5(req.body.password);
//     User.findOne({ email: username }, function (err, founduser) {
//         if (founduser) {
//             if (founduser.password === password) {
//                 res.render("secrets");
//             }
//         }
//     });
// })



//Using Hashing and salting
// app.post("/register", function (req, res) {
//     bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
//         const newuser = new User({
//             email: req.body.username,
//             password: hash
//         });
//         newuser.save(function (err) {
//             if (!err) {
//                 //Rendered here to attain some security
//                 res.render("secrets");
//             }
//         });
//     })

// });
// app.post("/login", function (req, res) {
//     const username = req.body.username;
//     const password = req.body.password;
//     User.findOne({ email: username }, function (err, founduser) {
//         if (founduser) {
//             bcrypt.compare(password, founduser.password, function (err, result) {

//                 if (result === true) {
//                     res.render("secrets");
//                 }
//             })
//         };
//     })
// })


app.post("/register", function (req, res) {
    User.register({ username: req.body.username }, req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            });
        }
    });
});
app.post("/login", function (req, res) {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    req.login(user, function (err) {
        if (!err) {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            });
        }
    });
})

app.listen(3000, function () { console.log("Server Running on 3000") })