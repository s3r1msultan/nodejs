import express from "express";
import pg from "pg";
import bcrypt from "bcrypt";
import { fileURLToPath } from "url";
import session from "express-session";
import path from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;
const { Pool } = pg;
const { hash, compare } = bcrypt;

const pool = new Pool({
  user: "root",
  host: "localhost",
  database: "users",
  password: "root",
  port: 5433,
});

app.use(
  session({
    secret: "your_secret_key",
    resave: false,
    saveUninitialized: true,
  })
);
app.use(express.urlencoded({ extended: false }));

app.use(express.json());

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/index.html");
});

app.get("/signup", (req, res) => {
  res.sendFile(__dirname + "/signup.html");
});

app.get("/signin", (req, res) => {
  res.sendFile(__dirname + "/signin.html");
});

app.post("/signup", async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await hash(password, 10);
  try {
    const result = await pool.query(
      "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id",
      [username, hashedPassword]
    );
    const userId = result.rows[0].id;
    req.session.userId = userId;
    res.send("Registration successful");
    res.redirect("/signin");
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});

app.post("/signin", async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await pool.query("SELECT * FROM users WHERE username = $1", [
      username,
    ]);

    if (result.rows.length === 0) {
      return res.status(401).send("Invalid username or password");
    }

    const user = result.rows[0];

    const isPasswordValid = await compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).send("Invalid username or password");
    }

    req.session.userId = user.id;

    res.send("Login successful");
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
