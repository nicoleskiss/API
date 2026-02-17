const express = require("express");
const mysql = require("mysql");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json()); 

const SECRET = "superhemlignyckel";

const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "api_db"
});

db.connect();

function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
        return res.status(401).json({ error: "Token saknas" });
    }

    jwt.verify(token, SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: "Ogiltig token" });
        }
        req.user = user;
        next();
    });
}

app.get("/", (req, res) => {
    res.json({
        message: "API-dokumentation",
        routes: {
            "POST /login": "Logga in, returnerar JWT (öppen)",
            "GET /users": "Hämta alla users (kräver token)",
            "GET /users/:id": "Hämta user via id (kräver token)",
            "POST /users": "Skapa ny user (kräver token)",
            "PUT /users/:id": "Uppdatera user (kräver token)"
        }
    });
});

app.post("/login", (req, res) => {
    const { username, password } = req.body;

    db.query(
        "SELECT * FROM users WHERE username = ?",
        [username],
        async (err, result) => {
            if (result.length === 0) {
                return res.status(401).json({ error: "Fel användarnamn" });
            }

            const user = result[0];
            const match = await bcrypt.compare(password, user.password);

            if (!match) {
                return res.status(401).json({ error: "Fel lösenord" });
            }

            const token = jwt.sign(
                { id: user.id, username: user.username },
                SECRET,
                { expiresIn: "1h" }
            );

            res.json({ token });
        }
    );
});

app.get("/users", authenticateToken, (req, res) => {
    db.query(
        "SELECT id, username, name FROM users",
        (err, result) => {
            res.json(result);
        }
    );
});

app.get("/users/:id", authenticateToken, (req, res) => {
    db.query(
        "SELECT id, username, name FROM users WHERE id = ?",
        [req.params.id],
        (err, result) => {
            if (result.length === 0) {
                return res.status(404).json({ error: "User hittades inte" });
            }
            res.json(result[0]);
        }
    );
});

app.post("/users", authenticateToken, async (req, res) => {
    const { username, password, name } = req.body;
    const hash = await bcrypt.hash(password, 10);

    db.query(
        "INSERT INTO users (username, password, name) VALUES (?, ?, ?)",
        [username, hash, name],
        (err, result) => {
            res.status(201).json({
                id: result.insertId,
                username,
                name
            });
        }
    );
});

app.put("/users/:id", authenticateToken, (req, res) => {
    const { name } = req.body;

    db.query(
        "UPDATE users SET name = ? WHERE id = ?",
        [name, req.params.id],
        () => {
            res.json({
                id: req.params.id,
                name
            });
        }
    );
});

app.listen(3000, () => {
    console.log("API körs på http://localhost:3000");
});
