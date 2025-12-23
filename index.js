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
app.use(express.json());
app.use(session({
  secret: "mysecretkey",
  resave: false,
  saveUninitialized: true
}));
app.use(express.static("public"));

// สร้าง table users อัตโนมัติ
(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `);
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
})();

// API register
app.post("/api/register", async (req,res)=>{
  const {username, password} = req.body;
  if(!username || !password) return res.json({success:false, msg:"กรอกข้อมูลไม่ครบ"});
  const hashed = await bcrypt.hash(password,10);
  try{
    await pool.query("INSERT INTO users(username,password) VALUES($1,$2)", [username,hashed]);
    res.json({success:true, msg:"สมัครสมาชิกเรียบร้อย"});
  }catch(err){
    if(err.code === '23505') res.json({success:false, msg:"Username นี้มีคนใช้แล้ว"});
    else res.json({success:false, msg:"เกิดข้อผิดพลาด"});
  }
});

// API login
app.post("/api/login", async (req,res)=>{
  const {username, password} = req.body;
  if(!username || !password) return res.json({success:false, msg:"กรอกข้อมูลไม่ครบ"});
  try{
    const result = await pool.query("SELECT * FROM users WHERE username=$1",[username]);
    if(result.rows.length===0) return res.json({success:false, msg:"ไม่พบผู้ใช้นี้"});
    const user = result.rows[0];
    const match = await bcrypt.compare(password,user.password);
    if(match){
      req.session.user = {id:user.id, username:user.username};
      res.json({success:true, msg:"Login สำเร็จ", username:user.username});
    }else{
      res.json({success:false, msg:"รหัสผ่านผิด"});
    }
  }catch(err){ res.json({success:false, msg:"เกิดข้อผิดพลาด"}); }
});

// API logout
app.post("/api/logout",(req,res)=>{
  req.session.destroy();
  res.json({success:true, msg:"Logout สำเร็จ"});
});
