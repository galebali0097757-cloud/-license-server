import express from "express";
import crypto from "node:crypto";
import Database from "better-sqlite3";

const app = express();
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: false }));

const db = new Database(process.env.DB_PATH || "./licenses.db");
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS licenses (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 key TEXT NOT NULL UNIQUE,
 status TEXT NOT NULL DEFAULT 'active',
 expires_at TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 last_seen_at TEXT
)`);

const ADMIN_TOKEN = process.env.ADMIN_TOKEN;
if (!ADMIN_TOKEN) console.warn("Set ADMIN_TOKEN before internet deployment.");

function admin(req,res,next) {
  const token = req.get("authorization")?.replace(/^Bearer\s+/i,"") || req.body.admin_token || req.query.admin_token;
  if (!ADMIN_TOKEN || token !== ADMIN_TOKEN) return res.status(401).json({ok:false,error:"unauthorized"});
  next();
}
function makeKey() {
  return crypto.randomBytes(12).toString("hex").toUpperCase().match(/.{1,6}/g).join("-");
}
function isValidKey(k) { return typeof k === "string" && /^[A-Z0-9-]{8,80}$/.test(k); }

app.use(express.static("."));

app.get("/health", (_req,res)=>res.json({ok:true,service:"license-server"}));

app.post("/v1/license/verify",(req,res)=>{
  const {key}=req.body||{};
  if(!isValidKey(key)) return res.status(400).json({ok:false,error:"invalid_key"});
  const row=db.prepare("SELECT key,status,expires_at FROM licenses WHERE key=?").get(key);
  if(!row) return res.status(404).json({ok:false,error:"invalid_license"});
  if(row.status!=="active") return res.status(403).json({ok:false,error:"license_"+row.status});
  if(row.expires_at && new Date(row.expires_at)<=new Date()){
    db.prepare("UPDATE licenses SET status='expired' WHERE key=?").run(key);
    return res.status(403).json({ok:false,error:"license_expired"});
  }
  db.prepare("UPDATE licenses SET last_seen_at=CURRENT_TIMESTAMP WHERE key=?").run(key);
  res.json({ok:true,key:row.key,expires_at:row.expires_at});
});

app.get("/v1/admin/licenses",admin,(req,res)=>{
  const rows=db.prepare("SELECT id,key,status,expires_at,created_at,last_seen_at FROM licenses ORDER BY id DESC").all();
  res.json({ok:true,licenses:rows});
});

app.post("/v1/admin/licenses",admin,(req,res)=>{
  const days=Number(req.body.days);
  if(!Number.isInteger(days)||days<1||days>3650) return res.status(400).json({ok:false,error:"invalid_days"});
  const key=makeKey();
  const expires=new Date(Date.now()+days*86400000).toISOString();
  db.prepare("INSERT INTO licenses(key,status,expires_at) VALUES(?,?,?)").run(key,"active",expires);
  res.json({ok:true,key,expires_at:expires});
});

app.post("/v1/admin/licenses/:key/revoke",admin,(req,res)=>{
  const r=db.prepare("UPDATE licenses SET status='revoked' WHERE key=?").run(req.params.key);
  res.json({ok:r.changes===1});
});

app.post("/v1/admin/licenses/:key/activate",admin,(req,res)=>{
  const r=db.prepare("UPDATE licenses SET status='active' WHERE key=?").run(req.params.key);
  res.json({ok:r.changes===1});
});

const port=Number(process.env.PORT||3000);
app.listen(port,()=>console.log(`Dashboard: http://localhost:${port}`));
