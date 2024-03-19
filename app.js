const express = require("express");
const mysql = require("mysql2");
const dotenv = require("dotenv");
const path = require("path");
const bcrypt = require("bcrypt"); // Added bcrypt for password hashing
const session = require("express-session"); // Added express-session for session management
const helmet = require("helmet"); // Added helmet for setting security headers
const rateLimit = require("express-rate-limit"); // Added express-rate-limit for rate limiting

const app = express();
app.set('view engine', 'hbs');
dotenv.config({ path: "./.env" });
const publicDir = path.join(__dirname, './webbsidan');

const db = mysql.createConnection({
    host: process.env.DATABASE_HOST,
    user: process.env.DATABASE_USER,
    password: process.env.DATABASE_PASSWORD,
    database: process.env.DATABASE
});

app.use(express.urlencoded({ extended: 'false' }));
app.use(express.json());
app.use(helmet()); // Use helmet to set security headers

// Configure session middleware
app.use(session({
    secret: process.env.SESSION_SECRET, // Use a strong secret key from environment variable
    resave: false,
    saveUninitialized: false
}));

// Configure rate limiting middleware
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // Limit each IP to 100 requests per windowMs
});
app.use(limiter);

db.connect((error) => {
    if (error) {
        console.error("Error connecting to MySQL:", error); // Proper error logging
    } else {
        console.log("Ansluten till MySQL");
    }
});

app.get("/", (req, res) => {
    res.render("index");
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.get("/login", (req, res) => {
    res.render("login");
});


app.post("/auth/register", async (req, res) => {
    const { name, email, password, password_confirm } = req.body;

    // Validate and sanitize user input
    if (!name || !email || !password || !password_confirm) {
        return res.render('register', {
            message: 'Alla fält måste fyllas i'
        });
    }

    if (password !== password_confirm) {
        return res.render('register', {
            message: 'Lösenorden matchar inte'
        });
    } else if (password.length < 8) {
        return res.render('register', {
            message: 'Lösenordet måste vara minst 8 tecken långt'
        });
    } else if (!password.match(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/)) {
        return res.render('register', {
            message: 'Lösenordet måste innehålla minst en stor bokstav, en liten bokstav och en siffra'
        });
    }

    if (!/\S+@\S+\.\S+/.test(email)) {
        return res.render('register', {
            message: 'Ogiltig e-postadress'
        });
    }

    try {
        // Check if the username is already taken
        db.query('SELECT * FROM users WHERE name = ?', [name], async (err, result) => {
            if (err) {
                console.error("Error checking username:", err);
                return res.render('register', {
                    message: 'Ett fel uppstod vid registrering'
                });
            }

            if (result.length > 0) {
                return res.render('register', {
                    message: 'Användarnamnet är redan taget'
                });
            }

            // Hash the password before storing it in the database
            const hashedPassword = await bcrypt.hash(password, 10);

            db.query('INSERT INTO users SET ?', { name: name, email: email, password: hashedPassword }, (err, result) => {
                if (err) {
                    console.error("Error registering user:", err);
                    return res.render('register', {
                        message: 'Ett fel uppstod vid registrering'
                    });
                } else {
                    return res.render('register', {
                        message: 'Användare registrerad'
                    });
                }
            });
        });
    } catch (error) {
        console.error("Error hashing password:", error);
        return res.render('register', {
            message: 'Ett fel uppstod vid registrering'
        });
    }
});

app.post("/auth/login", (req, res) => {
    const { name, password } = req.body;

    // Validate and sanitize user input
    if (!name || !password) {
        return res.render('login', {
            message: 'Alla fält måste fyllas i'
        });
    }

    db.query('SELECT * FROM users WHERE name = ?', [name], async (error, result) => {
        if (error) {
            console.error("Error logging in:", error);
            return res.render('login', {
                message: 'Ett fel uppstod vid inloggning'
            });
        }

        if (result.length === 0) {
            return res.render('login', {
                message: 'Användarnamnet finns inte registrerat'
            });
        } else {
            const user = result[0];

            try {
                // Compare the provided password with the hashed password in the database
                const passwordMatch = await bcrypt.compare(password, user.password);

                if (passwordMatch) {
                    // Set session data for authenticated user
                    req.session.userId = user.id;
                    req.session.username = user.name;

                    return res.render('login', {
                        message: 'Du är nu inloggad'
                    });
                } else {
                    return res.render('login', {
                        message: 'Fel lösenord'
                    });
                }
            } catch (error) {
                console.error("Error comparing passwords:", error);
                return res.render('login', {
                    message: 'Ett fel uppstod vid inloggning'
                });
            }
        }
    });
});

// Middleware to check if user is authenticated
const isAuthenticated = (req, res, next) => {
    if (req.session.userId) {
        next();
    } else {
        res.redirect('/login');
    }
};

// Protected route example
app.get("/profile", isAuthenticated, (req, res) => {
    res.render("profile", {
        username: req.session.username
    });
});

// Logout route
app.get("/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error("Error logging out:", err); // Proper error logging
        }
        res.redirect('/login');
    });
});

app.listen(4000, () => {
    console.log("Servern körs, besök http://localhost:4000");
});