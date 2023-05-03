require("./utils.js");
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;
const app = express();

const Joi = require("joi");

//Expires after 1 hour
const expireTime = 1 * 60 * 60 * 1000;

/* Secret Information Section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* End Secret Information Section */

var { database } = require("./databaseConnection");
const userCollection = database.db(mongodb_database).collection("users");

app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
});

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
})
);

function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req, res, next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}

function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", { error: "Not Authorized" });
        return;
    }
    else {
        next();
    }
}

app.get('/', (req, res) => {
    if (!req.session.authenticated) {
        res.render("index");
    }
    else {
        res.redirect('/loggedIn');
    }
});

app.get('/nosql-injection', async (req, res) => {
    var username = req.query.user;

    if (!username) {
        res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
        return;
    }
    console.log("user: " + username);

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);

    //If we didn't use Joi to validate and check for a valid URL parameter below
    // we could run our userCollection.find and it would be possible to attack.
    // A URL parameter of user[$ne]=name would get executed as a MongoDB command
    // and may result in revealing information about all users or a successful
    // login without knowing the correct password.
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
        return;
    }

    const result = await userCollection.find({ username: username }).project({ username: 1, password: 1, _id: 1 }).toArray();

    console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/about', (req, res) => {
    var color = req.query.color;

    res.render("about", { color: color });
});

app.get('/contact', (req, res) => {
    var missingEmail = req.query.missing;

    res.render("contact", { missing: missingEmail });
});

app.post('/submitEmail', (req, res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.render("submitEmail", { email: email });
    }
});


app.get('/signUp', (req, res) => {
    res.render("signUp");
});

// To do
app.post('/submitUser', async (req, res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object(
        {
            username: Joi.string().alphanum().max(20).required(),
            email: Joi.string().email().required(),
            password: Joi.string().max(20).required()
        });

    const validationResult = schema.validate({ username, email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        var errorMessage = validationResult.error.details[0].message;
        res.render('signUpError', { message: errorMessage });
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({
        username: username,
        email: email,
        password: hashedPassword,
        user_type: "user"
    });
    console.log("Inserted user");

    req.session.authenticated = true;
    req.session.username = username;

    res.redirect("/");
});

app.get('/login', (req, res) => {
    var msg = req.query.msg || '';

    res.render("login", { msg: msg })
});

app.post('/loggingin', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.string().required();
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect('/login?msg=Invalid Email/Password!');
        return;
    }

    const result = await userCollection.find({ email: email }).project({
        username: 1,
        email: 1,
        password: 1,
        user_type: 1,
        _id: 1
    }).toArray();

    console.log(result);
    if (result.length != 1) {
        console.log("User not found");
        res.redirect('/login?msg=Invalid Email/Password!');
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("Correct password");
        req.session.authenticated = true;
        req.session.username = result[0].username;
        req.session.email = email;
        req.session.user_type = result[0].user_type;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/loggedIn');
        return;
    }
    else {
        console.log("Incorrect password");
        res.redirect('/login?msg=Invalid Email/Password!');
        return;
    }
});

app.use('/loggedin', sessionValidation);
app.get('/loggedIn', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    } else {
        res.render('loggedIn', { username: req.session.username });
    }
});

app.get('/loggedin/info', (req, res) => {
    res.render("loggedin-info");
});

app.get("/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.log(err);
        } else {
            res.redirect("/");
        }
    });
});

const imageURL = [
    "piano.gif",
    "pot.gif",
    "tap.gif"
];

app.get('/cat/:id', (req, res) => {

    var cat = req.params.id;

    res.render("cat", { cat: cat });
});

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
        return;
    }

    const username = req.session.username;
    const imageIndex = Math.floor(Math.random() * imageURL.length);
    const image = imageURL[imageIndex];

    res.render("members", { username: username, image: image });
});

app.get('/admin', sessionValidation, adminAuthorization, async (req, res) => {
    const result = await userCollection.find().project({ username: 1, _id: 1 }).toArray();

    res.render("admin", { users: result });
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
    res.status(404);
    res.render("404");
});

app.listen(port, () => {
    console.log("Node application listening on port " + port);
});