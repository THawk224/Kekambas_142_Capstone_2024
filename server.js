const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
const app = express();
const port = 3000;
const jwt = require('jsonwebtoken');
const jwtSecret = 'your_jwt_secret';  // Keep this secret and secure

// Mock database storage for simplicity
let users = [];
let books = [];
let nextUserId = 1;
let nextBookId = 1;

app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'very secret secret',
    resave: false,
    saveUninitialized: false
}));
app.set('view engine', 'ejs');

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy(
    function(username, password, done) {
        const user = users.find(u => u.username === username);
        if (!user) {
            return done(null, false, { message: 'Incorrect username.' });
        }
        if (!bcrypt.compareSync(password, user.password)) {
            return done(null, false, { message: 'Incorrect password.' });
        }
        console.log(user)
        return done(null, user);
    }
));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
    const user = users.find(u => u.id === id);
    if (!user) {
        return done(new Error('user not found'));
    }
    done(null, user);
});
app.get("/", (req, res)=>{
    res.render('index')
})

// Registration endpoint
app.post('/register', (req, res) => {
    const { username, password } = req.body;
    if (users.some(u => u.username === username)) {
        return res.status(400).json({ error: 'Username already exists' });
    }
    const hashedPassword = bcrypt.hashSync(password, 10);
    const user = { id: nextUserId++, username, password: hashedPassword };
    users.push(user);
    res.json({ message: 'User registered' });
});

// Login endpoint
// app.post('/login', passport.authenticate('local'), (req, res) => {
//     res.json({ message: 'Logged in' });
// });
app.post('/login', passport.authenticate('local'), (req, res) => {
    console.log(req.user)
    const token = jwt.sign({ id: req.user.id }, jwtSecret, { expiresIn: '1h' });
    res.json({ message: 'Logged in', token });
});

// Logout endpoint
app.get('/logout', (req, res) => {
    req.logout();
    res.json({ message: 'Logged out' });
});

// Middleware to check if user is authenticated
function isAuthenticated(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.status(401).send({ error: 'Unauthorized' });

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) return res.status(403).send({ error: 'Forbidden' });
        req.user = user;
        next();
    });
}

// Define a protected route
app.get('/protected-route', isAuthenticated, (req, res) => {
    res.json({ message: 'You have accessed a protected area', user: req.user });
});

// Books endpoint: Get all books for logged-in user
app.get('/books', isAuthenticated, (req, res) => {
    const userBooks = books.filter(book => book.userId === req.user.id);
    res.json(userBooks);
});

// Books endpoint: Add a new book for logged-in user
app.post('/books', isAuthenticated, (req, res) => {
    const book = { id: nextBookId++, userId: req.user.id, title: req.body.title, author: req.body.author, genre: req.body.genre };
    books.push(book);
    res.json(book);
});

app.put('/books/:id', isAuthenticated, (req, res) => {
    const index = books.findIndex(book => book.id == req.params.id);
    if (index >= 0) {
      books[index] = { ...books[index], ...req.body };
      res.send(books[index]);
    } else {
      res.status(404).send({ message: 'Book not found' });
    }
  });

app.delete('/books/:id', isAuthenticated, (req, res) => {
    const index = books.findIndex(book => book.id == req.params.id);
    if (index >= 0) {
      books.splice(index, 1);
      res.send({ message: 'Book deleted' });
    } else {
      res.status(404).send({ message: 'Book not found' });
    }
  });

// Start the server
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
