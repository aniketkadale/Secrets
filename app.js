//jshint esversion:6
require("dotenv").config({ path: "vars/.env" });
require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

console.log(process.env.GOOGLE_CLIENT_ID);

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: "This is our little secret.",
  resave: false,
  saveUninitialized: false,
}));

app.use(passport.initialize());
app.use(passport.session());



mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  // useCreateIndex: true,
});

// mongoose.set("useCreateIndex", true);


// create schema to create users with email and passoword
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// create new user model using the userSchema
const User = mongoose.model("User", userSchema);
passport.use(User.createStrategy());

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id)
    .then(function (user) {
      done(null, user);
    })
    .catch(function (err) {
      console.error(err);
      done(err, null);
    });
});



passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    function (request, accessToken, refreshToken, profile, done) {
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return done(err, user);
      });
    }
  )
);


app.get("/", function (req, res) {
  res.render("home");
});

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    res.redirect("/secrets");
  }
);

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

// app.get("/secrets", function (req, res) {
//   User.find({"secret": {$ne: null}}, function(err, foundUsers) {
//     if(err) {
//       console.log(err);
//     } else {
//       if(foundUsers) {
//         res.render("secrets", {usersWithSecrets: foundUsers});
//       }
//     }
//   })
// });

// The above code is old, the find method in mongodb no longer accept callbacks. So use this👇🏻

app.get("/secrets", function (req, res) {
  User.find({ secret: { $ne: null } })
    .then((foundUsers) => {
      if (foundUsers && foundUsers.length > 0) {
        res.render("secrets", { usersWithSecrets: foundUsers });
      } else {
        // Handle the case when no users with secrets are found
        res.render("secrets", { usersWithSecrets: [] });
      }
    })
    .catch((err) => {
      console.error(err);
      // Handle the error appropriately, e.g., render an error page
      res.status(500).send("Internal Server Error");
    });
});


app.get("/submit", function(req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
})

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    return res.redirect("/");
  });
});




// register the user, once registered show him the 'secrets' page
app.post("/register", function (req, res) {
    User.register({username: req.body.username}, req.body.password, function(err, user) {
      if(err) {
        console.log(err);
        res.redirect('/register');
      } else {
        passport.authenticate('local')(req, res, function() {
          res.redirect('/secrets');
        })
      }
    })
});

// login
app.post("/login", async function (req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });

  req.login(user, function(err) {
    if(err) {
      console.log(err);
    } else {
      passport.authenticate('local')(req, res, function() {
        res.redirect('/secrets');
      });
    }
  });
});


app.post("/submit", function(req, res) {
  const userSecret = req.body.secret;
  // passport automatically saves the current logged in user in the req variable

  User.findById(req.user.id)
    .then((foundUser) => {
      if (foundUser) {
        foundUser.secret = userSecret;
        return foundUser.save();
      }
    })
    .then(() => {
      res.redirect("/secrets");
    })
    .catch((err) => {
      console.error(err);
    });

})



app.listen(3000, function () {
  console.log("Server is running on port 3000");
});
