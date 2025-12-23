const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: "mysecretkey",
  resave: false,
  saveUninitialized: true
}));
app.use(express.static("public"));

app.get("/", (req, res) => {
  if(req.session.user) {
    res.send(`<h1>ยินดีต้อนรับ ${req.session.user.username}</h1>
              <a href="/logout">Logout</a>`);
  } else {
    res.sendFile(__dirname + "/public/index.html");
  }
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  try {
    await pool.query("INSERT INTO users(username,password) VALUES($1,$2)", [username, hashed]);
    res.redirect("/login.html");
  } catch (err) {
    res.send("มีปัญหา: " + err);
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const result = await pool.query("SELECT * FROM users WHERE username=$1", [username]);
  if(result.rows.length > 0){
    const user = result.rows[0];
    if(await bcrypt.compare(password, user.password)){
      req.session.user = { id: user.id, username: user.username };
      res.redirect("/");
    } else {
      res.send("รหัสผ่านผิด");
    }
  } else {
    res.send("ไม่มีผู้ใช้นี้");
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
