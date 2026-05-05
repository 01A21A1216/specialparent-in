#!/usr/bin/env python3
"""
SpecialParent.in — Full Backend API
Flask + SQLite3 (built-in) + JWT Authentication
"""
import sqlite3
import bcrypt
import uuid
import json
import os
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify, g
from flask_cors import CORS
import jwt as pyjwt

app = Flask(__name__)
CORS(app, origins=["http://localhost:5173","http://127.0.0.1:5173","http://localhost:3000"], 
     supports_credentials=True, allow_headers=["Content-Type","Authorization"])

# ── CONFIG ──────────────────────────────────────────
JWT_SECRET = os.getenv("JWT_SECRET", "specialparent_jwt_2025_secure_key")
JWT_ALGO = "HS256"
JWT_EXPIRES_DAYS = 7
# Use /tmp on cloud (Railway), or local database/ folder
_local_db = os.path.join(os.path.dirname(__file__), "database", "specialparent.db")
os.makedirs(os.path.join(os.path.dirname(__file__), "database"), exist_ok=True)
DB_PATH = os.environ.get("DB_PATH", _local_db)

# ── DATABASE ──────────────────────────────────────────
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def db():
    return get_db()

def query(sql, params=(), one=False):
    cur = db().execute(sql, params)
    db().commit()
    if one:
        row = cur.fetchone()
        return dict(row) if row else None
    return [dict(r) for r in cur.fetchall()]

def execute(sql, params=()):
    cur = db().execute(sql, params)
    db().commit()
    return cur

# ── SCHEMA INIT ──────────────────────────────────────────
def init_db():
    d = get_db()
    d.executescript("""
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  phone TEXT,
  city TEXT,
  role TEXT DEFAULT 'parent',
  avatar_initials TEXT,
  is_verified INTEGER DEFAULT 0,
  otp_code TEXT,
  otp_expires INTEGER,
  reset_token TEXT,
  reset_expires INTEGER,
  created_at INTEGER DEFAULT (strftime('%s','now')),
  updated_at INTEGER DEFAULT (strftime('%s','now'))
);
CREATE TABLE IF NOT EXISTS children (
  id TEXT PRIMARY KEY,
  parent_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  nickname TEXT,
  dob TEXT,
  gender TEXT,
  blood_group TEXT,
  home_language TEXT DEFAULT 'Hindi',
  avatar TEXT DEFAULT '🦋',
  profile_color TEXT DEFAULT '#059669',
  diagnosis TEXT,
  diagnosis_level INTEGER DEFAULT 2,
  diagnosis_date TEXT,
  diagnosing_doctor TEXT,
  comorbidities TEXT,
  school_name TEXT,
  school_type TEXT,
  primary_therapist TEXT,
  session_length TEXT,
  sessions_per_week TEXT,
  therapy_days TEXT DEFAULT '[]',
  teacher_notes TEXT,
  medications TEXT,
  allergies TEXT,
  responder_notes TEXT,
  ec1_name TEXT,
  ec1_phone TEXT,
  ec2_name TEXT,
  ec2_phone TEXT,
  doctor_name TEXT,
  doctor_phone TEXT,
  created_at INTEGER DEFAULT (strftime('%s','now')),
  updated_at INTEGER DEFAULT (strftime('%s','now'))
);
CREATE TABLE IF NOT EXISTS development_scores (
  id TEXT PRIMARY KEY,
  child_id TEXT NOT NULL REFERENCES children(id) ON DELETE CASCADE,
  speech INTEGER DEFAULT 50,
  social INTEGER DEFAULT 35,
  sensory INTEGER DEFAULT 45,
  motor INTEGER DEFAULT 60,
  emotional INTEGER DEFAULT 30,
  communication INTEGER DEFAULT 40,
  recorded_at INTEGER DEFAULT (strftime('%s','now')),
  notes TEXT
);
CREATE TABLE IF NOT EXISTS goals (
  id TEXT PRIMARY KEY,
  child_id TEXT NOT NULL REFERENCES children(id) ON DELETE CASCADE,
  created_by TEXT,
  title TEXT NOT NULL,
  description TEXT,
  category TEXT DEFAULT 'speech',
  goal_type TEXT DEFAULT 'short',
  status TEXT DEFAULT 'pending',
  target_date TEXT,
  progress INTEGER DEFAULT 0,
  created_at INTEGER DEFAULT (strftime('%s','now')),
  updated_at INTEGER DEFAULT (strftime('%s','now'))
);
CREATE TABLE IF NOT EXISTS goal_updates (
  id TEXT PRIMARY KEY,
  goal_id TEXT NOT NULL REFERENCES goals(id) ON DELETE CASCADE,
  updated_by TEXT,
  old_status TEXT,
  new_status TEXT,
  old_progress INTEGER,
  new_progress INTEGER,
  note TEXT,
  created_at INTEGER DEFAULT (strftime('%s','now'))
);
CREATE TABLE IF NOT EXISTS therapy_sessions (
  id TEXT PRIMARY KEY,
  child_id TEXT NOT NULL REFERENCES children(id) ON DELETE CASCADE,
  therapy_type TEXT NOT NULL,
  session_date TEXT NOT NULL,
  duration_minutes INTEGER DEFAULT 45,
  status TEXT DEFAULT 'scheduled',
  therapist_name TEXT,
  location TEXT,
  notes TEXT,
  parent_feedback TEXT,
  goals_worked TEXT DEFAULT '[]',
  created_at INTEGER DEFAULT (strftime('%s','now')),
  updated_at INTEGER DEFAULT (strftime('%s','now'))
);
CREATE TABLE IF NOT EXISTS concerns (
  id TEXT PRIMARY KEY,
  child_id TEXT NOT NULL REFERENCES children(id) ON DELETE CASCADE,
  concern TEXT NOT NULL,
  category TEXT,
  created_at INTEGER DEFAULT (strftime('%s','now'))
);
CREATE TABLE IF NOT EXISTS assessments (
  id TEXT PRIMARY KEY,
  child_id TEXT NOT NULL REFERENCES children(id) ON DELETE CASCADE,
  assessment_type TEXT NOT NULL,
  assessment_date TEXT,
  conducted_by TEXT,
  hospital TEXT,
  summary TEXT,
  created_at INTEGER DEFAULT (strftime('%s','now'))
);
CREATE TABLE IF NOT EXISTS medications (
  id TEXT PRIMARY KEY,
  child_id TEXT NOT NULL REFERENCES children(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  dosage TEXT,
  frequency TEXT,
  prescribed_by TEXT,
  start_date TEXT,
  is_active INTEGER DEFAULT 1,
  notes TEXT,
  created_at INTEGER DEFAULT (strftime('%s','now'))
);
CREATE TABLE IF NOT EXISTS community_posts (
  id TEXT PRIMARY KEY,
  author_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  group_name TEXT DEFAULT 'general',
  content TEXT NOT NULL,
  likes INTEGER DEFAULT 0,
  replies_count INTEGER DEFAULT 0,
  is_pinned INTEGER DEFAULT 0,
  created_at INTEGER DEFAULT (strftime('%s','now')),
  updated_at INTEGER DEFAULT (strftime('%s','now'))
);
CREATE TABLE IF NOT EXISTS notifications (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  message TEXT,
  type TEXT DEFAULT 'info',
  is_read INTEGER DEFAULT 0,
  created_at INTEGER DEFAULT (strftime('%s','now'))
);
""")
    d.commit()

# ── AUTH HELPERS ──────────────────────────────────────────
def hash_password(pw): return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(12)).decode()
def verify_password(pw, h): return bcrypt.checkpw(pw.encode(), h.encode())
def gen_token(payload):
    payload = {**payload, "exp": datetime.now(timezone.utc) + timedelta(days=JWT_EXPIRES_DAYS)}
    return pyjwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)
def gen_otp(): return str(uuid.uuid4().int)[:6].zfill(6)
def new_id(): return str(uuid.uuid4())
def safe_user(u):
    drop = {"password_hash","otp_code","otp_expires","reset_token","reset_expires"}
    return {k:v for k,v in u.items() if k not in drop}

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        header = request.headers.get("Authorization","")
        if not header.startswith("Bearer "):
            return jsonify({"error":"Unauthorized"}), 401
        try:
            payload = pyjwt.decode(header[7:], JWT_SECRET, algorithms=[JWT_ALGO])
            g.user = payload
        except pyjwt.ExpiredSignatureError:
            return jsonify({"error":"Token expired"}), 401
        except Exception:
            return jsonify({"error":"Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated

# ── ERROR HANDLERS ──────────────────────────────────────────
@app.errorhandler(404)
def not_found(e): return jsonify({"error":"Not found"}), 404

@app.errorhandler(500)
def server_error(e): return jsonify({"error":"Internal server error"}), 500

# ════════════════════════════════════════
#  HEALTH
# ════════════════════════════════════════
@app.get("/api/health")
def health():
    return jsonify({"status":"ok","timestamp":datetime.now().isoformat()})

@app.get("/api/stats")
def stats():
    users = query("SELECT COUNT(*) as cnt FROM users",one=True)["cnt"]
    children = query("SELECT COUNT(*) as cnt FROM children",one=True)["cnt"]
    sessions = query("SELECT COUNT(*) as cnt FROM therapy_sessions",one=True)["cnt"]
    goals = query("SELECT COUNT(*) as cnt FROM goals WHERE status='completed'",one=True)["cnt"]
    return jsonify({"families":users,"children":children,"sessions":sessions,"goals_completed":goals})

# ════════════════════════════════════════
#  AUTH ROUTES
# ════════════════════════════════════════
@app.post("/api/auth/register")
def register():
    d = request.json or {}
    email = (d.get("email","")).strip().lower()
    password = d.get("password","")
    first_name = d.get("first_name","").strip()
    last_name = d.get("last_name","").strip()
    phone = d.get("phone","").strip() or None
    city = d.get("city","").strip() or None
    role = d.get("role","parent")

    if not all([email, password, first_name, last_name]):
        return jsonify({"error":"Email, password, first and last name are required"}), 400
    if len(password) < 8:
        return jsonify({"error":"Password must be at least 8 characters"}), 400
    if query("SELECT id FROM users WHERE email=?", (email,), one=True):
        return jsonify({"error":"An account with this email already exists"}), 409

    uid = new_id()
    ph = hash_password(password)
    initials = (first_name[0] + (last_name[0] if last_name else "")).upper()
    otp = gen_otp()
    otp_exp = int(time.time()*1000) + 10*60*1000

    execute("INSERT INTO users (id,email,password_hash,first_name,last_name,phone,city,role,avatar_initials,otp_code,otp_expires) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (uid, email, ph, first_name, last_name, phone, city, role, initials, otp, otp_exp))
    execute("INSERT INTO notifications (id,user_id,title,message,type) VALUES (?,?,?,?,?)",
            (new_id(), uid, "Welcome to SpecialParent.in! 🎉", "Your account is ready. Start by adding your child's profile.", "info"))

    token = gen_token({"id":uid,"email":email,"role":role})
    user = query("SELECT * FROM users WHERE id=?", (uid,), one=True)
    return jsonify({"message":"Account created","token":token,"user":safe_user(user),"otp_demo":otp}), 201

@app.post("/api/auth/login")
def login():
    d = request.json or {}
    email = (d.get("email","")).strip().lower()
    password = d.get("password","")
    if not email or not password:
        return jsonify({"error":"Email and password are required"}), 400
    user = query("SELECT * FROM users WHERE email=?", (email,), one=True)
    if not user or not verify_password(password, user["password_hash"]):
        return jsonify({"error":"Invalid email or password"}), 401
    token = gen_token({"id":user["id"],"email":user["email"],"role":user["role"]})
    return jsonify({"token":token,"user":safe_user(user)})

@app.post("/api/auth/verify-otp")
@require_auth
def verify_otp():
    otp = str(request.json.get("otp",""))
    user = query("SELECT * FROM users WHERE id=?", (g.user["id"],), one=True)
    if not user: return jsonify({"error":"User not found"}), 404
    if user["otp_code"] != otp: return jsonify({"error":"Invalid OTP code"}), 400
    if int(time.time()*1000) > (user["otp_expires"] or 0): return jsonify({"error":"OTP has expired"}), 400
    execute("UPDATE users SET is_verified=1,otp_code=NULL,otp_expires=NULL WHERE id=?", (user["id"],))
    return jsonify({"message":"Email verified successfully"})

@app.post("/api/auth/resend-otp")
@require_auth
def resend_otp():
    otp = gen_otp()
    execute("UPDATE users SET otp_code=?,otp_expires=? WHERE id=?",
            (otp, int(time.time()*1000)+10*60*1000, g.user["id"]))
    return jsonify({"message":"OTP resent","otp_demo":otp})

@app.post("/api/auth/forgot-password")
def forgot_password():
    email = (request.json or {}).get("email","").strip().lower()
    user = query("SELECT id FROM users WHERE email=?", (email,), one=True)
    if user:
        token = new_id().replace("-","")
        execute("UPDATE users SET reset_token=?,reset_expires=? WHERE id=?",
                (token, int(time.time()*1000)+30*60*1000, user["id"]))
    return jsonify({"message":"If that email exists, a reset link has been sent"})

@app.post("/api/auth/reset-password")
def reset_password():
    d = request.json or {}
    token, password = d.get("token"), d.get("password")
    if not token or not password: return jsonify({"error":"Token and password required"}), 400
    user = query("SELECT * FROM users WHERE reset_token=?", (token,), one=True)
    if not user or int(time.time()*1000) > (user["reset_expires"] or 0):
        return jsonify({"error":"Reset link is invalid or expired"}), 400
    execute("UPDATE users SET password_hash=?,reset_token=NULL,reset_expires=NULL WHERE id=?",
            (hash_password(password), user["id"]))
    return jsonify({"message":"Password reset successfully"})

@app.get("/api/auth/me")
@require_auth
def get_me():
    user = query("SELECT * FROM users WHERE id=?", (g.user["id"],), one=True)
    if not user: return jsonify({"error":"User not found"}), 404
    return jsonify(safe_user(user))

@app.patch("/api/auth/me")
@require_auth
def update_me():
    d = request.json or {}
    execute("UPDATE users SET first_name=COALESCE(?,first_name),last_name=COALESCE(?,last_name),phone=COALESCE(?,phone),city=COALESCE(?,city),updated_at=strftime('%s','now') WHERE id=?",
            (d.get("first_name"), d.get("last_name"), d.get("phone"), d.get("city"), g.user["id"]))
    return jsonify(safe_user(query("SELECT * FROM users WHERE id=?", (g.user["id"],), one=True)))

# ════════════════════════════════════════
#  CHILDREN ROUTES
# ════════════════════════════════════════
def enrich_child(c):
    if isinstance(c, dict):
        c["therapy_days"] = json.loads(c.get("therapy_days") or "[]")
        ds = query("SELECT * FROM development_scores WHERE child_id=? ORDER BY recorded_at DESC LIMIT 1", (c["id"],), one=True)
        c["dev"] = {"speech":ds["speech"] if ds else 50,"social":ds["social"] if ds else 35,
                     "sensory":ds["sensory"] if ds else 45,"motor":ds["motor"] if ds else 60,
                     "emotional":ds["emotional"] if ds else 30,"communication":ds["communication"] if ds else 40}
        gc = query("SELECT status FROM goals WHERE child_id=?", (c["id"],))
        c["goals_total"] = len(gc)
        c["goals_completed"] = sum(1 for g in gc if g["status"]=="completed")
        today = datetime.now().strftime("%Y-%m-%d")
        sc = query("SELECT status,session_date FROM therapy_sessions WHERE child_id=?", (c["id"],))
        c["upcoming_sessions"] = sum(1 for s in sc if s["status"]=="scheduled" and s["session_date"]>=today)
        c["concerns_count"] = query("SELECT COUNT(*) as n FROM concerns WHERE child_id=?", (c["id"],), one=True)["n"]
    return c

@app.get("/api/children")
@require_auth
def get_children():
    children = query("SELECT * FROM children WHERE parent_id=? ORDER BY created_at ASC", (g.user["id"],))
    return jsonify([enrich_child(c) for c in children])

@app.get("/api/children/<cid>")
@require_auth
def get_child(cid):
    child = query("SELECT * FROM children WHERE id=? AND parent_id=?", (cid, g.user["id"]), one=True)
    if not child: return jsonify({"error":"Child not found"}), 404
    child = enrich_child(child)
    child["dev_scores"] = query("SELECT * FROM development_scores WHERE child_id=? ORDER BY recorded_at ASC", (cid,))
    child["goals"] = query("SELECT * FROM goals WHERE child_id=? ORDER BY created_at DESC", (cid,))
    child["sessions"] = [dict(s,goals_worked=json.loads(s.get("goals_worked") or "[]")) 
                          for s in query("SELECT * FROM therapy_sessions WHERE child_id=? ORDER BY session_date DESC LIMIT 20", (cid,))]
    child["concerns"] = query("SELECT * FROM concerns WHERE child_id=?", (cid,))
    child["assessments"] = query("SELECT * FROM assessments WHERE child_id=? ORDER BY created_at DESC", (cid,))
    child["medications"] = query("SELECT * FROM medications WHERE child_id=? AND is_active=1", (cid,))
    return jsonify(child)

@app.post("/api/children")
@require_auth
def create_child():
    d = request.json or {}
    if not d.get("name"): return jsonify({"error":"Child name is required"}), 400
    cid = new_id()
    execute("""INSERT INTO children (id,parent_id,name,nickname,dob,gender,blood_group,home_language,
        avatar,profile_color,diagnosis,diagnosis_level,diagnosis_date,diagnosing_doctor,comorbidities,
        school_name,school_type,primary_therapist,session_length,sessions_per_week,therapy_days,teacher_notes,
        medications,allergies,responder_notes,ec1_name,ec1_phone,ec2_name,ec2_phone,doctor_name,doctor_phone)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (cid,g.user["id"],d["name"],d.get("nickname"),d.get("dob"),d.get("gender"),
         d.get("blood_group"),d.get("home_language","Hindi"),d.get("avatar","🦋"),d.get("profile_color","#059669"),
         d.get("diagnosis"),d.get("diagnosis_level",2),d.get("diagnosis_date"),d.get("diagnosing_doctor"),d.get("comorbidities"),
         d.get("school_name"),d.get("school_type"),d.get("primary_therapist"),d.get("session_length"),d.get("sessions_per_week"),
         json.dumps(d.get("therapy_days",[])),d.get("teacher_notes"),d.get("medications"),
         d.get("allergies"),d.get("responder_notes"),d.get("ec1_name"),d.get("ec1_phone"),
         d.get("ec2_name"),d.get("ec2_phone"),d.get("doctor_name"),d.get("doctor_phone")))
    
    dev = d.get("dev_scores",{})
    execute("INSERT INTO development_scores (id,child_id,speech,social,sensory,motor,emotional,communication,notes) VALUES (?,?,?,?,?,?,?,?,?)",
            (new_id(),cid,dev.get("speech",50),dev.get("social",35),dev.get("sensory",45),
             dev.get("motor",60),dev.get("emotional",30),dev.get("communication",40),"Initial baseline"))

    for c in d.get("concerns",[]):
        execute("INSERT INTO concerns (id,child_id,concern) VALUES (?,?,?)", (new_id(),cid,c))

    auto_goals = [
        ("Eye contact 5 seconds","Practice during mirror games, bubble play, and daily activities","social","short",30),
        ("Use 10 new words independently","PECS cards, visual aids, daily narration activities","speech","short",30),
        ("Sit for 20-minute therapy session","Build attention and tolerance for structured therapy gradually","emotional","short",30),
        ("Practice turn-taking in play","Board games and structured play to develop social skills","social","short",30),
        ("Independent communication","Express needs using words, AAC, or signs","speech","long",180),
        ("School integration milestones","Achieve readiness for inclusive classroom participation","social","long",180),
    ]
    today = datetime.now()
    for title, desc, cat, gtype, days in auto_goals:
        tdate = (today + timedelta(days=days)).strftime("%Y-%m-%d")
        execute("INSERT INTO goals (id,child_id,created_by,title,description,category,goal_type,target_date) VALUES (?,?,?,?,?,?,?,?)",
                (new_id(),cid,g.user["id"],title,desc,cat,gtype,tdate))

    execute("INSERT INTO notifications (id,user_id,title,message,type) VALUES (?,?,?,?,?)",
            (new_id(),g.user["id"],f"{d['name']}'s profile created! 🌟",
             f"We've set up {d['name']}'s baseline and suggested 6 personalised goals.","success"))

    child = query("SELECT * FROM children WHERE id=?", (cid,), one=True)
    return jsonify(enrich_child(child)), 201

@app.patch("/api/children/<cid>")
@require_auth
def update_child(cid):
    if not query("SELECT id FROM children WHERE id=? AND parent_id=?", (cid, g.user["id"]), one=True):
        return jsonify({"error":"Child not found"}), 404
    d = request.json or {}
    fields = ["name","nickname","dob","gender","blood_group","home_language","avatar","profile_color",
              "diagnosis","diagnosis_level","diagnosis_date","diagnosing_doctor","comorbidities",
              "school_name","school_type","primary_therapist","session_length","sessions_per_week",
              "teacher_notes","medications","allergies","responder_notes",
              "ec1_name","ec1_phone","ec2_name","ec2_phone","doctor_name","doctor_phone"]
    updates = {k:d[k] for k in fields if k in d}
    if "therapy_days" in d:
        updates["therapy_days"] = json.dumps(d["therapy_days"])
    if not updates: return jsonify({"error":"No fields to update"}), 400
    set_clause = ",".join(f"{k}=?" for k in updates)
    execute(f"UPDATE children SET {set_clause},updated_at=strftime('%s','now') WHERE id=?",
            list(updates.values())+[cid])
    return jsonify(enrich_child(query("SELECT * FROM children WHERE id=?", (cid,), one=True)))

@app.delete("/api/children/<cid>")
@require_auth
def delete_child(cid):
    if not query("SELECT id FROM children WHERE id=? AND parent_id=?", (cid, g.user["id"]), one=True):
        return jsonify({"error":"Child not found"}), 404
    execute("DELETE FROM children WHERE id=?", (cid,))
    return jsonify({"message":"Child profile deleted"})

@app.get("/api/children/<cid>/dev-scores")
@require_auth
def get_dev_scores(cid):
    if not query("SELECT id FROM children WHERE id=? AND parent_id=?", (cid, g.user["id"]), one=True):
        return jsonify({"error":"Child not found"}), 404
    return jsonify(query("SELECT * FROM development_scores WHERE child_id=? ORDER BY recorded_at ASC", (cid,)))

@app.post("/api/children/<cid>/dev-scores")
@require_auth
def add_dev_score(cid):
    if not query("SELECT id FROM children WHERE id=? AND parent_id=?", (cid, g.user["id"]), one=True):
        return jsonify({"error":"Child not found"}), 404
    d = request.json or {}
    sid = new_id()
    execute("INSERT INTO development_scores (id,child_id,speech,social,sensory,motor,emotional,communication,notes) VALUES (?,?,?,?,?,?,?,?,?)",
            (sid,cid,d.get("speech",50),d.get("social",35),d.get("sensory",45),
             d.get("motor",60),d.get("emotional",30),d.get("communication",40),d.get("notes")))
    return jsonify(query("SELECT * FROM development_scores WHERE id=?", (sid,), one=True)), 201

# ════════════════════════════════════════
#  GOALS
# ════════════════════════════════════════
@app.get("/api/children/<cid>/goals")
@require_auth
def get_goals(cid):
    if not query("SELECT id FROM children WHERE id=? AND parent_id=?", (cid, g.user["id"]), one=True):
        return jsonify({"error":"Child not found"}), 404
    return jsonify(query("SELECT * FROM goals WHERE child_id=? ORDER BY created_at DESC", (cid,)))

@app.post("/api/children/<cid>/goals")
@require_auth
def create_goal(cid):
    if not query("SELECT id FROM children WHERE id=? AND parent_id=?", (cid, g.user["id"]), one=True):
        return jsonify({"error":"Child not found"}), 404
    d = request.json or {}
    if not d.get("title"): return jsonify({"error":"Goal title is required"}), 400
    gid = new_id()
    execute("INSERT INTO goals (id,child_id,created_by,title,description,category,goal_type,status,target_date) VALUES (?,?,?,?,?,?,?,?,?)",
            (gid,cid,g.user["id"],d["title"],d.get("description"),
             d.get("category","speech"),d.get("goal_type","short"),d.get("status","pending"),d.get("target_date")))
    return jsonify(query("SELECT * FROM goals WHERE id=?", (gid,), one=True)), 201

@app.patch("/api/goals/<gid>")
@require_auth
def update_goal(gid):
    goal = query("SELECT g.* FROM goals g JOIN children c ON g.child_id=c.id WHERE g.id=? AND c.parent_id=?", (gid, g.user["id"]), one=True)
    if not goal: return jsonify({"error":"Goal not found"}), 404
    d = request.json or {}
    status = d.get("status")
    progress = d.get("progress")
    if status or progress is not None:
        execute("INSERT INTO goal_updates (id,goal_id,updated_by,old_status,new_status,old_progress,new_progress,note) VALUES (?,?,?,?,?,?,?,?)",
                (new_id(),gid,g.user["id"],goal["status"],status or goal["status"],
                 goal["progress"],progress if progress is not None else goal["progress"],d.get("note")))
    execute("UPDATE goals SET status=COALESCE(?,status),progress=COALESCE(?,progress),title=COALESCE(?,title),description=COALESCE(?,description),target_date=COALESCE(?,target_date),updated_at=strftime('%s','now') WHERE id=?",
            (status,progress,d.get("title"),d.get("description"),d.get("target_date"),gid))
    return jsonify(query("SELECT * FROM goals WHERE id=?", (gid,), one=True))

@app.delete("/api/goals/<gid>")
@require_auth
def delete_goal(gid):
    goal = query("SELECT g.id FROM goals g JOIN children c ON g.child_id=c.id WHERE g.id=? AND c.parent_id=?", (gid, g.user["id"]), one=True)
    if not goal: return jsonify({"error":"Goal not found"}), 404
    execute("DELETE FROM goals WHERE id=?", (gid,))
    return jsonify({"message":"Goal deleted"})

# ════════════════════════════════════════
#  THERAPY SESSIONS
# ════════════════════════════════════════
@app.get("/api/children/<cid>/sessions")
@require_auth
def get_sessions(cid):
    if not query("SELECT id FROM children WHERE id=? AND parent_id=?", (cid, g.user["id"]), one=True):
        return jsonify({"error":"Child not found"}), 404
    status_filter = request.args.get("status")
    if status_filter:
        sessions = query("SELECT * FROM therapy_sessions WHERE child_id=? AND status=? ORDER BY session_date DESC LIMIT 30", (cid, status_filter))
    else:
        sessions = query("SELECT * FROM therapy_sessions WHERE child_id=? ORDER BY session_date DESC LIMIT 30", (cid,))
    return jsonify([dict(s,goals_worked=json.loads(s.get("goals_worked") or "[]")) for s in sessions])

@app.post("/api/children/<cid>/sessions")
@require_auth
def create_session(cid):
    if not query("SELECT id FROM children WHERE id=? AND parent_id=?", (cid, g.user["id"]), one=True):
        return jsonify({"error":"Child not found"}), 404
    d = request.json or {}
    if not d.get("therapy_type") or not d.get("session_date"):
        return jsonify({"error":"therapy_type and session_date required"}), 400
    sid = new_id()
    execute("INSERT INTO therapy_sessions (id,child_id,therapy_type,session_date,duration_minutes,status,therapist_name,location,notes,goals_worked) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (sid,cid,d["therapy_type"],d["session_date"],d.get("duration_minutes",45),
             d.get("status","scheduled"),d.get("therapist_name"),d.get("location"),d.get("notes"),
             json.dumps(d.get("goals_worked",[]))))
    s = query("SELECT * FROM therapy_sessions WHERE id=?", (sid,), one=True)
    return jsonify(dict(s,goals_worked=json.loads(s.get("goals_worked") or "[]"))), 201

@app.patch("/api/sessions/<sid>")
@require_auth
def update_session(sid):
    s = query("SELECT ts.id FROM therapy_sessions ts JOIN children c ON ts.child_id=c.id WHERE ts.id=? AND c.parent_id=?", (sid, g.user["id"]), one=True)
    if not s: return jsonify({"error":"Session not found"}), 404
    d = request.json or {}
    execute("UPDATE therapy_sessions SET status=COALESCE(?,status),notes=COALESCE(?,notes),parent_feedback=COALESCE(?,parent_feedback),duration_minutes=COALESCE(?,duration_minutes),therapist_name=COALESCE(?,therapist_name),updated_at=strftime('%s','now') WHERE id=?",
            (d.get("status"),d.get("notes"),d.get("parent_feedback"),d.get("duration_minutes"),d.get("therapist_name"),sid))
    s = query("SELECT * FROM therapy_sessions WHERE id=?", (sid,), one=True)
    return jsonify(dict(s,goals_worked=json.loads(s.get("goals_worked") or "[]")))

# ════════════════════════════════════════
#  ASSESSMENTS
# ════════════════════════════════════════
@app.get("/api/children/<cid>/assessments")
@require_auth
def get_assessments(cid):
    if not query("SELECT id FROM children WHERE id=? AND parent_id=?", (cid, g.user["id"]), one=True):
        return jsonify({"error":"Child not found"}), 404
    return jsonify(query("SELECT * FROM assessments WHERE child_id=? ORDER BY created_at DESC", (cid,)))

@app.post("/api/children/<cid>/assessments")
@require_auth
def create_assessment(cid):
    if not query("SELECT id FROM children WHERE id=? AND parent_id=?", (cid, g.user["id"]), one=True):
        return jsonify({"error":"Child not found"}), 404
    d = request.json or {}
    if not d.get("assessment_type"): return jsonify({"error":"assessment_type required"}), 400
    aid = new_id()
    execute("INSERT INTO assessments (id,child_id,assessment_type,assessment_date,conducted_by,hospital,summary) VALUES (?,?,?,?,?,?,?)",
            (aid,cid,d["assessment_type"],d.get("assessment_date"),d.get("conducted_by"),d.get("hospital"),d.get("summary")))
    return jsonify(query("SELECT * FROM assessments WHERE id=?", (aid,), one=True)), 201

# ════════════════════════════════════════
#  MEDICATIONS
# ════════════════════════════════════════
@app.get("/api/children/<cid>/medications")
@require_auth
def get_medications(cid):
    if not query("SELECT id FROM children WHERE id=? AND parent_id=?", (cid, g.user["id"]), one=True):
        return jsonify({"error":"Child not found"}), 404
    return jsonify(query("SELECT * FROM medications WHERE child_id=? AND is_active=1 ORDER BY created_at DESC", (cid,)))

@app.post("/api/children/<cid>/medications")
@require_auth
def create_medication(cid):
    if not query("SELECT id FROM children WHERE id=? AND parent_id=?", (cid, g.user["id"]), one=True):
        return jsonify({"error":"Child not found"}), 404
    d = request.json or {}
    if not d.get("name"): return jsonify({"error":"Medication name required"}), 400
    mid = new_id()
    execute("INSERT INTO medications (id,child_id,name,dosage,frequency,prescribed_by,start_date,notes) VALUES (?,?,?,?,?,?,?,?)",
            (mid,cid,d["name"],d.get("dosage"),d.get("frequency"),d.get("prescribed_by"),d.get("start_date"),d.get("notes")))
    return jsonify(query("SELECT * FROM medications WHERE id=?", (mid,), one=True)), 201

@app.patch("/api/medications/<mid>/deactivate")
@require_auth
def deactivate_medication(mid):
    execute("UPDATE medications SET is_active=0 WHERE id=?", (mid,))
    return jsonify({"message":"Medication deactivated"})

# ════════════════════════════════════════
#  NOTIFICATIONS
# ════════════════════════════════════════
@app.get("/api/notifications")
@require_auth
def get_notifications():
    return jsonify(query("SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 30", (g.user["id"],)))

@app.patch("/api/notifications/<nid>/read")
@require_auth
def read_notification(nid):
    execute("UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?", (nid, g.user["id"]))
    return jsonify({"message":"Marked as read"})

@app.patch("/api/notifications/read-all")
@require_auth
def read_all_notifications():
    execute("UPDATE notifications SET is_read=1 WHERE user_id=?", (g.user["id"],))
    return jsonify({"message":"All notifications marked as read"})

# ════════════════════════════════════════
#  COMMUNITY
# ════════════════════════════════════════
@app.get("/api/community")
@require_auth
def get_community():
    group = request.args.get("group","general")
    limit = int(request.args.get("limit",20))
    offset = int(request.args.get("offset",0))
    posts = query("""SELECT cp.*,u.first_name,u.last_name,u.avatar_initials,u.city
        FROM community_posts cp JOIN users u ON cp.author_id=u.id
        WHERE cp.group_name=? ORDER BY cp.is_pinned DESC, cp.created_at DESC LIMIT ? OFFSET ?""",
        (group,limit,offset))
    return jsonify(posts)

@app.post("/api/community")
@require_auth
def create_post():
    d = request.json or {}
    content = (d.get("content","")).strip()
    if len(content) < 5: return jsonify({"error":"Post content too short"}), 400
    pid = new_id()
    execute("INSERT INTO community_posts (id,author_id,group_name,content) VALUES (?,?,?,?)",
            (pid,g.user["id"],d.get("group_name","general"),content))
    post = query("SELECT cp.*,u.first_name,u.last_name,u.avatar_initials,u.city FROM community_posts cp JOIN users u ON cp.author_id=u.id WHERE cp.id=?", (pid,), one=True)
    return jsonify(post), 201

@app.post("/api/community/<pid>/like")
@require_auth
def like_post(pid):
    execute("UPDATE community_posts SET likes=likes+1 WHERE id=?", (pid,))
    post = query("SELECT likes FROM community_posts WHERE id=?", (pid,), one=True)
    return jsonify({"likes":post["likes"] if post else 0})

# ════════════════════════════════════════
#  DASHBOARD SUMMARY
# ════════════════════════════════════════
@app.get("/api/dashboard")
@require_auth
def dashboard():
    uid = g.user["id"]
    children = query("SELECT id,name,avatar,profile_color,diagnosis FROM children WHERE parent_id=?", (uid,))
    child_ids = [c["id"] for c in children]
    goals_total = goals_done = sessions_upcoming = sessions_done = 0
    if child_ids:
        ph = ",".join("?"*len(child_ids))
        goals = query(f"SELECT status FROM goals WHERE child_id IN ({ph})", child_ids)
        goals_total = len(goals)
        goals_done = sum(1 for g_ in goals if g_["status"]=="completed")
        today = datetime.now().strftime("%Y-%m-%d")
        sessions = query(f"SELECT status,session_date FROM therapy_sessions WHERE child_id IN ({ph})", child_ids)
        sessions_upcoming = sum(1 for s in sessions if s["status"]=="scheduled" and s["session_date"]>=today)
        sessions_done = sum(1 for s in sessions if s["status"]=="completed")
    unread = query("SELECT COUNT(*) as n FROM notifications WHERE user_id=? AND is_read=0", (uid,), one=True)["n"]
    recent = query("SELECT cp.*,u.first_name,u.last_name,u.avatar_initials FROM community_posts cp JOIN users u ON cp.author_id=u.id ORDER BY cp.created_at DESC LIMIT 3")
    return jsonify({
        "children_count":len(children),"goals_total":goals_total,"goals_completed":goals_done,
        "upcoming_sessions":sessions_upcoming,"total_sessions":sessions_done,
        "unread_notifications":unread,"recent_community":recent
    })

# ════════════════════════════════════════
#  SEED ON FIRST RUN
# ════════════════════════════════════════
def seed_demo_data():
    with app.app_context():
        init_db()
        if query("SELECT id FROM users WHERE email=?", ("demo@sp.in",), one=True):
            return  # Already seeded

        uid = str(uuid.uuid4())
        c1 = str(uuid.uuid4())
        c2 = str(uuid.uuid4())
        ph = hash_password("Demo@1234")

        execute("INSERT INTO users (id,email,password_hash,first_name,last_name,phone,city,role,avatar_initials,is_verified) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (uid,"demo@sp.in",ph,"Kavita","Sharma","+91 98765 43210","Mumbai","parent","KS",1))

        execute("""INSERT INTO children (id,parent_id,name,nickname,dob,gender,blood_group,avatar,profile_color,
            diagnosis,diagnosis_level,diagnosis_date,diagnosing_doctor,school_name,school_type,primary_therapist,
            session_length,sessions_per_week,therapy_days,ec1_name,ec1_phone,medications,allergies)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (c1,uid,"Arjun Sharma","Ari","2019-03-15","Boy","O+","🦁","#059669",
             "ASD — Autism Spectrum Disorder",2,"2021-06","Dr. Rekha Nair",
             "Rainbow Academy","Special school","Dr. Rekha Nair",
             "45 minutes","3",json.dumps(["Mon","Wed","Fri"]),
             "Kavita Sharma","+91 98765 43210","Risperidone 0.5mg — once daily morning","No known allergies"))

        execute("""INSERT INTO children (id,parent_id,name,dob,gender,blood_group,avatar,profile_color,
            diagnosis,diagnosis_level,school_name,school_type,session_length,sessions_per_week,therapy_days,ec1_name,ec1_phone)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (c2,uid,"Priya Sharma","2021-07-22","Girl","B+","🌻","#3B82F6",
             "ADHD",1,"Sunrise School","Inclusive/mainstream school",
             "30 minutes","2",json.dumps(["Tue","Thu"]),"Kavita Sharma","+91 98765 43210"))

        # Dev scores history for Arjun
        for speech,social,sensory,motor,emot,comm,notes in [
            (45,30,40,55,25,35,"Initial assessment — Jun 2021"),
            (60,42,52,65,38,50,"Six-month review — Dec 2021"),
            (70,48,61,68,42,66,"Current baseline — May 2025")]:
            execute("INSERT INTO development_scores (id,child_id,speech,social,sensory,motor,emotional,communication,notes) VALUES (?,?,?,?,?,?,?,?,?)",
                    (str(uuid.uuid4()),c1,speech,social,sensory,motor,emot,comm,notes))
        execute("INSERT INTO development_scores (id,child_id,speech,social,sensory,motor,emotional,communication,notes) VALUES (?,?,?,?,?,?,?,?,?)",
                (str(uuid.uuid4()),c2,75,65,55,70,45,72,"Priya baseline"))

        today = datetime.now()
        m1 = (today+timedelta(days=30)).strftime("%Y-%m-%d")
        m6 = (today+timedelta(days=180)).strftime("%Y-%m-%d")
        goals_data = [
            (c1,uid,"Eye contact 5 seconds","Practice mirror games and bubble play","social","short","completed",100,m1),
            (c1,uid,"Use 10 new words independently","PECS cards + daily narration","speech","short","completed",100,m1),
            (c1,uid,"Sit for 20-min therapy session","Build tolerance gradually","emotional","short","in_progress",50,m1),
            (c1,uid,"Practice turn-taking in play","Board games and structured play","social","short","pending",0,m1),
            (c1,uid,"Follow 2-step instructions","Visual cue cards + repetition","cognitive","short","pending",0,m1),
            (c1,uid,"Independent communication","AAC device + verbal expansion","speech","long","in_progress",35,m6),
            (c1,uid,"School integration","Gradual mainstream inclusion","social","long","pending",10,m6),
            (c2,uid,"Focus for 15 minutes","Use visual timer and preferred activity","emotional","short","in_progress",60,m1),
        ]
        for cid,by,title,desc,cat,gtype,status,prog,tdate in goals_data:
            execute("INSERT INTO goals (id,child_id,created_by,title,description,category,goal_type,status,progress,target_date) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (str(uuid.uuid4()),cid,by,title,desc,cat,gtype,status,prog,tdate))

        sessions_data = [
            (c1,"speech","2025-04-28",45,"completed","Dr. Rekha Nair","KEM Hospital","Used 4 new words spontaneously. Excellent requesting vocab session."),
            (c1,"aba","2025-04-30",60,"completed","Vikas Sharma","Home visit","18/20 DTT trials successful. Beginning generalisation."),
            (c1,"occupational","2025-05-02",45,"completed","Anjali OT","Priya OT Centre","Good fine motor. Scissors and button activities."),
            (c1,"speech","2025-05-06",45,"scheduled","Dr. Rekha Nair","KEM Hospital",None),
            (c1,"occupational","2025-05-08",45,"scheduled","Anjali OT","Priya OT Centre",None),
            (c1,"aba","2025-05-10",60,"scheduled","Vikas Sharma","Home visit",None),
            (c2,"speech","2025-05-07",30,"scheduled","Ms. Pooja","Sunrise School",None),
        ]
        for cid,ttype,sdate,dur,status,tname,loc,notes in sessions_data:
            execute("INSERT INTO therapy_sessions (id,child_id,therapy_type,session_date,duration_minutes,status,therapist_name,location,notes,goals_worked) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (str(uuid.uuid4()),cid,ttype,sdate,dur,status,tname,loc,notes,"[]"))

        for concern in ["Eye contact","Speech delays","Sensory overload","Meltdowns","School inclusion","Social skills"]:
            execute("INSERT INTO concerns (id,child_id,concern) VALUES (?,?,?)", (str(uuid.uuid4()),c1,concern))
        for concern in ["Focus","Impulsivity","Organisation"]:
            execute("INSERT INTO concerns (id,child_id,concern) VALUES (?,?,?)", (str(uuid.uuid4()),c2,concern))

        for atype,adate,by,hosp,summary in [
            ("ADOS-2 Diagnostic Assessment","2021-06-15","Dr. Rekha Nair","KEM Hospital","Confirmed ASD Level 2. Strong visual learning profile."),
            ("IQ & Cognitive Assessment","2021-08-10","Dr. Vikram Patel","Nanavati Hospital","IQ 82. Visual-spatial strengths. Language processing delayed."),
            ("Speech & Language Evaluation","2021-09-05","Dr. Rekha Nair","KEM Hospital","Receptive 2.5yr level. Expressive 1.8yr level."),
        ]:
            execute("INSERT INTO assessments (id,child_id,assessment_type,assessment_date,conducted_by,hospital,summary) VALUES (?,?,?,?,?,?,?)",
                    (str(uuid.uuid4()),c1,atype,adate,by,hosp,summary))

        execute("INSERT INTO medications (id,child_id,name,dosage,frequency,prescribed_by,start_date) VALUES (?,?,?,?,?,?,?)",
                (str(uuid.uuid4()),c1,"Risperidone","0.5mg","Once daily, morning","Dr. Vikram Patel","2022-01-10"))
        execute("INSERT INTO medications (id,child_id,name,dosage,frequency,notes) VALUES (?,?,?,?,?,?)",
                (str(uuid.uuid4()),c1,"Omega-3 supplement","1000mg","Once daily with food","As recommended by nutritionist"))

        notifs = [
            (uid,"Arjun's session tomorrow! 📅","Speech therapy at 10 AM — Dr. Rekha Nair","reminder"),
            (uid,"Goal completed! 🎉","Arjun completed 'Use 10 new words independently'! Great progress.","success"),
            (uid,"Community post","Priya R. shared tips on reducing sensory overload at school.","info"),
            (uid,"Welcome to SpecialParent.in! 🎉","Your account is ready. Start by adding your child's profile.","info"),
        ]
        for user_id,title,msg,ntype in notifs:
            execute("INSERT INTO notifications (id,user_id,title,message,type) VALUES (?,?,?,?,?)", (str(uuid.uuid4()),user_id,title,msg,ntype))

        posts_data = [
            (uid,"mumbai","Has anyone tried PECS for non-verbal children at home? Arjun is 4 and we're struggling with tantrums before meals. Any parents with experience?",42,18),
            (uid,"general","GREAT NEWS: Got Niramaya insurance approved after 3 months! Key: disability certificate from CMO first, then UDID card. Happy to guide anyone — DM me!",128,54),
            (uid,"bangalore","Looking for inclusive school recommendations in Koramangala for ASD Level 1, age 6. Personal experiences welcome!",23,31),
        ]
        for author_id,group,content,likes,replies in posts_data:
            execute("INSERT INTO community_posts (id,author_id,group_name,content,likes,replies_count) VALUES (?,?,?,?,?,?)",
                    (str(uuid.uuid4()),author_id,group,content,likes,replies))

        print("✅ Database seeded! demo@sp.in / Demo@1234")

# Always init and seed on startup (works with both gunicorn and direct run)
with app.app_context():
    try:
        init_db()
        seed_demo_data()
        print("✅ DB ready: demo@sp.in / Demo@1234")
    except Exception as e:
        print(f"⚠️ DB init error: {e}")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3001))
    print(f"\n🌿 SpecialParent.in API → http://localhost:{port}")
    print("🔑 Demo: demo@sp.in / Demo@1234\n")
    app.run(host="0.0.0.0", port=port, debug=False)
