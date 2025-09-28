from flask import Flask, render_template, request, redirect,session,jsonify, url_for
from flask_mail import Mail,Message
import  mysql.connector
import re
import os, time
from random import randint
import random
import hashlib
import sqlite3
from datetime import datetime, timedelta
import secrets
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import json
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
import base64
import os
from functools import wraps
from werkzeug.utils import secure_filename
from twilio.rest import Client
from openai import OpenAI
from difflib import get_close_matches
# from flask import flash
from email_validator import validate_email, EmailNotValidError
import smtplib, ssl, random
from flask_bcrypt import Bcrypt, generate_password_hash 
app = Flask(__name__)
app.secret_key="your_secret_key"
client = OpenAI(api_key="YOUR_OPENAI_API_KEY")  
mail=Mail(app)


# Sample in-memory database
users = {
    '12345678901': 'password123'
}


#password = data.get('password', '')strip()

    #if not all([name, phone, gender, password]):

       # return "jsonify({"error":"missing fields"}), 400

    
        #user = get_user_by_phone(phone)
       # if user and user['password'] == password:   
         #  session['username'] = user  # Store user in session
           #return redirect('/dashboard')
            
        #else:
            #return render_template('login.html', message="Invalid credentials.")
   # return render_template('login.html')


#@app.route('/dashboard')
#def dashboard():
    #user = session.get('user')
    #return render_template('dashboard.html', user=user)










    

@app.route('/')
def index():
    return render_template('index.html')




#


# CORS(app)  # allows frontend fetch to work

# # SQLite DB for demo
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///zestpay.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT']=465
app.config['MAIL_USERNAME']="zestpayexchange@gmail.com"
app.config['MAIL_PASSWORD']="rbhy vche lvmu btkb"
app.config['MAIL_USE_TLS']=False
app.config['MAIL_USE_SSL']=True
app.config['MAIL_DEFAULT_SENDER'] = app.config['MAIL_USERNAME']
mail = Mail(app)
otp=randint(100000,999999)
# ========== User Model ==========
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(50))
    lastName = db.Column(db.String(50))
    phone = db.Column(db.String(11))
    referral = db.Column(db.String(50))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    #profilePic = db.Column(db.String(260), nullable=False)  #
# ========== Register ==========
    
    
    
    # is_verified = db.Column(db.Boolean, default=False)
    # otp = db.Column(db.String(6))
    # otp_expiry = db.Column(db.DateTime)



@app.route("/register", methods=["GET","POST"])
def register():
    if not request.is_json:
        return render_template('register.html')

    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"status": "error", "message": "Invalid JSON"}), 400

    email = data.get("email")
    phone = data.get("phone")
    password = data.get("password")

    if not email or not password or not phone:
        return jsonify({"status": "error", "message": "Missing fields"}), 400

    # ✅ Validate email format
    try:
        validate_email(email)  # throws error if invalid
    except EmailNotValidError:
        return jsonify({"status": "invalid_email"}), 400

    # ✅ Check if email already exists
    if User.query.filter_by(email=email).first():
        return jsonify({"status": "email_exists"}), 400

    # ✅ Check if phone number already exists
    if User.query.filter_by(phone=phone).first():
        return jsonify({"status": "phone_exists"}), 400

    # ✅ Basic phone format check (Nigeria example: 11 digits)
    if not re.fullmatch(r"^\d{11}$", phone):
        return jsonify({"status": "invalid_phone"}), 400

    # ✅ Save user
    hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
    new_user = User(
        firstName=data.get("firstName"),
        lastName=data.get("lastName"),
        phone=phone,
        referral=data.get("referral"),
        email=email,
        password=hashed_pw
    )
    db.session.add(new_user)
    db.session.commit()

    # ✅ Send welcome email
    try:
        msg = Message(
            subject="🎉 WELCOME TO ZESTPAY!",
            recipients=[email]
        )
        msg.body = f"""
Hello {data.get("firstName") or ""},

🎉 Welcome to ZestPay — your account has been created successfully!

Here’s what you can do with ZestPay:
- ✅ Send & receive payments instantly
- 📊 Track your transactions in real-time
- 🎁 Earn rewards with referrals
- 🔒 Enjoy secure and fast services

⚡ Login now and start exploring: https://zestpay.com/login

We’re excited to have you onboard 

The ZestPay Team
"""
        mail.send(msg)
    except Exception as e:
        print("❌ Welcome email send failed:", e)

    return jsonify({"status": "ok"})


# ========== Login ==========
@app.route("/login", methods=["GET","POST"])
def login():
    if not request.is_json:
        return render_template('login.html')

    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"status": "error", "message": "Invalid JSON"}), 400

    email = data.get("email")
    password = data.get("password")

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"status": "invalid"})

    if bcrypt.check_password_hash(user.password, password):
        # ✅ set session for web pages
        session['user_email'] = user.email
        session['user_firstName'] = user.firstName or ""
        session['user_lastName'] = user.lastName or ""

        # ✅ send login email
        try:
            msg = Message(
                subject="👋 Welcome back to ZestPay!",
                recipients=[user.email]
            )
            msg.body = f"""
Hello {user.firstName or ''},

You have successfully logged in to your ZestPay account ✅

Stay tuned for new features and updates 

If you need our help, you can contact us on Email:zestexchange@gmail.com


The ZestPay Team
"""
            mail.send(msg)
        except Exception as e:
            print("❌ Login email failed:", e)

        return jsonify({"status": "ok", "user": {"email": user.email, "firstName": user.firstName}})
    else:
        return jsonify({"status": "invalid"})





def login_required_session(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_email' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


# --- Dashboard and related pages ---
@app.route("/dashboard")
@login_required_session
def dashboard():
    # dashboard.html will fetch profile via AJAX, but we can send name for server-rendered display
    first = session.get('user_firstName') or ""
    email = session.get('user_email')
    return render_template("dashboard.html", firstName=first, email=email)

@app.route("/profile")
@login_required_session
def profile_page():
    return render_template("profile.html")

@app.route("/settings")
@login_required_session
def settings_page():
    return render_template("settings.html")

@app.route("/rates")
@login_required_session
def rates_page():
    return render_template("rates.html")

@app.route("/cards")
@login_required_session
def cards_page():
    return render_template("cards.html")


# --- API: get current user's profile ---
@app.route("/api/profile", methods=["GET"])
def api_get_profile():
    if 'user_email' not in session:
        return jsonify({"status":"unauthenticated"}), 401
    user = User.query.filter_by(email=session['user_email']).first()

   
    if not user:
        return jsonify({"status":"not_found"}), 404
    return jsonify({
        "status": "ok",
        "profile": {
            "firstName": user.firstName,
            "lastName": user.lastName,
            "phone": user.phone,
            "referral": user.referral,
            "email": user.email
        }
    })




#-- API: update profile from settings page ---
@app.route("/api/profile", methods=["GET","POST"])
def api_update_profile():
    if 'user_email' not in session:
        return jsonify({"status":"unauthenticated"}), 401
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status":"error", "message":"Invalid JSON"}), 400

    user = User.query.filter_by(email=session['user_email']).first()
    if not user:
        return jsonify({"status":"not_found"}), 404

    # Update allowed fields
    user.firstName = data.get("firstName", user.firstName)
    user.lastName = data.get("lastName", user.lastName)
    user.phone = data.get("phone", user.phone)
    user.referral = data.get("referral", user.referral)
    # email update: optionally allow, but must ensure uniqueness
    
    
    new_email = data.get("email", user.email)
    if new_email != user.email:
        if User.query.filter_by(email=new_email).first():
            return jsonify({"status":"error", "message":"email_exists"}), 400
        user.email = new_email
        # update session email if changed
        session['user_email'] = new_email

    db.session.commit()

    # update stored session names
    session['user_firstName'] = user.firstName or ""
    session['user_lastName'] = user.lastName or ""

    return jsonify({"status":"ok", "profile": {
        "firstName": user.firstName,
        "lastName": user.lastName,
        "phone": user.phone,
        "referral": user.referral,
        "email": user.email
    }})


# --- Logout ---
@app.route("/logout")
def logout():
    session_keys = ['user_email', 'user_firstName', 'user_lastName']
    for k in session_keys:
        session.pop(k, None)
    return redirect(url_for('login'))




# --- Ensure 'profilePic' column exists in your User model ---
# Add this to your User model:
# profilePic = db.Column(db.String(200), nullable=True)

# --- API: Upload Profile Picture ---

# UPLOAD_FOLDER = 'static/uploads'
# os.makedirs(UPLOAD_FOLDER, exist_ok=True)
# app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# --- Helper function ---
# def allowed_file(filename):
    # return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS


# --- Profile picture upload endpoint ---
# @app.route('/api/uploadProfilePic', methods=['POST'])
# @login_required_session
# def upload_profile_pic():
    # if 'profilePic' not in request.files:
        # return jsonify({'status': 'error', 'message': 'No file part in request'}), 400

    # file = request.files['profilePic']

    # if file.filename == '':
        # return jsonify({'status': 'error', 'message': 'No file selected'}), 400
# 
    # if file and allowed_file(file.filename):
        # filename = secure_filename(file.filename)
        # user_email = session['user_email']
        # ext = filename.rsplit('.', 1)[1].lower()
        # Make filename unique
        # user_filename = f"{user_email}_{int(time.time())}.{ext}"
        # filepath = os.path.join(app.config['UPLOAD_FOLDER'], user_filename)
        # file.save(filepath)
# 
        # Save relative path in DB for frontend
        # user = User.query.filter_by(email=user_email).first()
        # if user:
            # user.profilePic = f"uploads/{user_filename}"  # relative to 'static/'
            # db.session.commit()
            # return jsonify({'status': 'ok', 'file': user.profilePic})
        # else:
            # return jsonify({'status': 'error', 'message': 'User not found'}), 404
    # else:
        # return jsonify({'status': 'error', 'message': 'Invalid file type'}),

# ================= AI Assistant Route =================
# ================= AI Assistant Route =================
# Keep a simple in-memory chat history (can switch to DB for persistence)



# -------------------------
# Simple SQLite Q&A Memory
# -------------------------



# -------------------------
# AI Route
# -------------------------
# ==========================
# AI Assistant (ZestPay)


# Load API key from environment


# Simple in-memory chat history (per session)
# ==========================
# AI Assistant (ZestPay) - Smart with Smalltalk
# ==========================

chat_history = {}

# --- SQLite Memory ---
# ==========================
# ZestPay AI Assistant (v2) 
# Owner: David Afiakurue
# ==========================


# --- Init AI Memory DB ---
def init_ai_memory():
    conn = sqlite3.connect("zestpay_ai.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS memory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            question TEXT,
            answer TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_answer(question, answer):
    conn = sqlite3.connect("zestpay_ai.db")
    c = conn.cursor()
    c.execute("INSERT INTO memory (question, answer) VALUES (?, ?)", (question, answer))
    conn.commit()
    conn.close()

def get_stored_answer(user_input):
    conn = sqlite3.connect("zestpay_ai.db")
    c = conn.cursor()
    c.execute("SELECT question, answer FROM memory")
    rows = c.fetchall()
    conn.close()

    if not rows:
        return None

    questions = [r[0] for r in rows]
    matches = get_close_matches(user_input, questions, n=1, cutoff=0.7)
    if matches:
        for q, a in rows:
            if q == matches[0]:
                return a
    return None


# --- TalkSmart Bank (1000+ entries) ---
talksmart = {
    # Greetings
    "hi": "Hello 👋 How can I help you today?",
    "hello": "Hey there! 😊",
    "hey": "Hi 👋 What’s up?",
    "yo": "Yo 😎 How’s it going?",
    "sup": "Not much, just here to help you with ZestPay!",
    "good morning": "Good morning ☀️ Hope your day is going well!",
    "good afternoon": "Good afternoon 🌞 How can I assist you?",
    "good evening": "Good evening 🌙 Ready to explore ZestPay?",
    "good night": "Good night 🌙 Rest well!",
    "okay":"sure",
    "hwfar": "i dey oo",
    "howfar": "i dey oo",

    # Feelings
    "fine": "Glad to hear you’re fine! 👍",
    "i am fine": "Awesome! 😊 Do you want to check your balance or explore?",
    "how are you": "I’m doing great, thanks for asking! How are you?",
    "i am okay": "Good to know 👍 What’s next on your mind?",

    # Thanks
    "thanks": "You’re welcome! 🙏",
    "thank you": "Anytime! Happy to help 👍",
    "tnx": "You’re welcome! 💯",

    # Fun words
    "lol": "😂 Haha, glad you’re having fun!",
    "lmao": "🤣 That’s hilarious!",
    "omg": "😲 Oh wow!",

    # Bye
    "bye": "Goodbye 👋 See you again soon.",
    "see you": "See you later! 👋",
    "take care": "You too! Stay safe ✨",

    # ZestPay Info
    "who owns zestpay": "ZestPay is owned by David Afiakurue — a visionary entrepreneur passionate about financial technology, innovation, and making payments seamless.",
    "what is zestpay": "ZestPay is a smart digital platform for payments, cards, and seamless financial services.",
    "tell me about zestpay": "ZestPay helps you send, receive, and manage money with ease. Secure, fast, and reliable!",
    "who is david afiakurue": "David Afiakurue is the founder of ZestPay. He is dedicated to building modern payment systems that empower people worldwide.",
    "about david afiakurue": "David Afiakurue is a fintech innovator and entrepreneur. He created ZestPay to solve real financial challenges with smart technology.",

    # Quick actions
    "login": "Sure, I’ll take you to the login page.",
    "register": "Let’s get you signed up on ZestPay!",
    "dashboard": "Opening your dashboard 🖥️",
    "cards": "Here are your cards 💳",
    "rates": "Fetching today’s rates 📊",
    "profile": "Opening your profile 👤",
    "settings": "Going to settings ⚙️",
    "logout": "Logging you out. Come back soon 👋",
    "supports": "chat with support on whatsapp",
    "get": "sure, taking you to home page",

    # Placeholder: More smalltalks/slangs/FAQs (fill up to 1000+)
}
# Tip: You can extend talksmart easily with JSON file if list gets very long.


# --- AI Chat Route ---
@app.route("/api/ai", methods=["GET","POST"])
def ai():
    data = request.get_json(silent=True)
    if not data or "prompt" not in data:
        return jsonify({"error": "No prompt provided"}), 400

    user_id = session.get("user_id", "guest")
    prompt = data["prompt"].strip()
    lower_prompt = prompt.lower()

    if user_id not in chat_history:
        chat_history[user_id] = []

    chat_history[user_id].append({"role": "user", "content": prompt})

    # Step 1: Smalltalk / TalkSmart detection
    for key, response in talksmart.items():
        if key in lower_prompt:
            chat_history[user_id].append({"role": "assistant", "content": response})

            # Handle redirects for certain actions
            actions = {
                "login": "/login",
                "register": "/register",
                "dashboard": "/dashboard",
                "rates": "/rates",
                "cards": "/cards",
                "profile": "/profile",
                "settings": "/settings",
                "logout": "/logout",
                "supports": "https://wa.me/2348026544598",
                "get":"/get"
            }
            if key in actions:
                return jsonify({"reply": response, "action": "redirect", "redirect_url": actions[key]})

            return jsonify({"reply": response, "action": "message"})

    # Step 2: Check stored memory
    stored = get_stored_answer(lower_prompt)
    if stored:
        chat_history[user_id].append({"role": "assistant", "content": stored})
        return jsonify({"reply": stored, "action": "message"})

    # Step 3: Fallback to OpenAI
    try:
        messages = [
            {
                "role": "system",
                "content": (
                    "You are ZestPay's AI assistant. "
                    "Always reply in clear English. "
                    "Detect intent even if user types slang, misspellings, or broken words. "
                    "You must know that ZestPay is owned by David Afiakurue and answer about him if asked."
                )
            }
        ]
        messages.extend(chat_history[user_id][-10:])

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages
        )

        reply = response.choices[0].message.content.strip()

        save_answer(lower_prompt, reply)
        chat_history[user_id].append({"role": "assistant", "content": reply})

        return jsonify({"reply": reply, "action": "message"})

    except Exception as e:
        print("AI backend error:", e)
        return jsonify({"error": "AI request failed", "details": str(e)}), 500




@app.route('/get')
def get():
    return render_template('get.html')




# --- API: Update Profile ---
# @app.route("/api/profile", methods=["GET","POST"])
# @login_required_session
# def api_update_profile():
#     if 'user_email' not in session:
#         return jsonify({"status": "unauthenticated"}), 401

#     data = request.get_json(silent=True)
#     if not data:
#         return jsonify({"status": "error", "message": "Invalid JSON"}), 400

#     user = User.query.filter_by(email=session['user_email']).first()
#     if not user:
#         return jsonify({"status": "not_found"}), 404

#     # Update allowed fields
#     user.firstName = data.get("firstName", user.firstName)
#     user.lastName = data.get("lastName", user.lastName)
#     user.phone = data.get("phone", user.phone)

#     new_email = data.get("email", user.email)
#     if new_email != user.email:
#         if User.query.filter_by(email=new_email).first():
#             return jsonify({"status": "error", "message": "email_exists"}), 400
#         user.email = new_email
#         session['user_email'] = new_email

#     db.session.commit()
#     return jsonify({"status": "ok"})






@app.route("/api/account/deactivate", methods=["GET","POST"])
@login_required_session
def api_deactivate_account():
    user = User.query.filter_by(email=session['user_email']).first()
    if not user:
        return jsonify({"status":"not_found"}), 404
    # Add a simple "deactivated" flag instead of deleting immediately
    user.referral = "DEACTIVATED"   # just placeholder for demo
    db.session.commit()
    return jsonify({"status":"ok", "message":"Account deactivated"})


@app.route("/api/account/delete", methods=["POST"])
@login_required_session
def api_delete_account():
    user = User.query.filter_by(email=session['user_email']).first()
    if not user:
        return jsonify({"status":"not_found"}), 404

    db.session.delete(user)
    db.session.commit()

    # logout after deleting
    session.clear()
    return jsonify({"status":"ok", "message":"Account deleted"})

#
# Simple table for notifications
class NotificationSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120))
    email_alerts = db.Column(db.Boolean, default=False)
    sms_alerts = db.Column(db.Boolean, default=False)

# Save notifications
@app.route("/api/notifications", methods=["GET","POST"])
@login_required_session
def api_notifications():
    data = request.get_json(silent=True)
    if not data: return jsonify({"status":"error"}), 400

    user_email = session['user_email']
    setting = NotificationSetting.query.filter_by(user_email=user_email).first()
    if not setting:
        setting = NotificationSetting(user_email=user_email)
        db.session.add(setting)

    setting.email_alerts = data.get("email_alerts", False)
    setting.sms_alerts = data.get("sms_alerts", False)

    db.session.commit()
    return jsonify({"status":"ok"})




@app.route("/api/security/password", methods=["GET","POST"])
@login_required_session
def api_change_password():
    data = request.get_json(silent=True)
    if not data: return jsonify({"status":"error"}), 400

    new_pw = data.get("password")
    confirm_pw = data.get("confirm")

    if not new_pw or new_pw != confirm_pw:
        return jsonify({"status":"error", "message":"Passwords do not match"}), 400

    user = User.query.filter_by(email=session['user_email']).first()
    if not user: return jsonify({"status":"not_found"}), 404

    user.password = bcrypt.generate_password_hash(new_pw).decode("utf-8")
    db.session.commit()
    return jsonify({"status":"ok", "message":"Password updated"})






















# -------------------
# Database Model
# -------------------

# -------------------
# Helper: send OTP email
# -------------------
# def send_otp_email(to_email, otp):
#     try:
#         sender = "dominionafiakurue@gmail.com"
#         password = "D0rc@s12345#"

#         msg = MIMEText(f"Your ZestPay verification code is {otp}. It expires in 5 minutes.")
#         msg["Subject"] = "ZestPay OTP Verification"
#         msg["From"] = sender
#         msg["To"] = to_email

#         with smtplib.SMTP("smtp.gmail.com", 587) as server:
#             server.starttls()
#             server.login(sender, password)
#             server.sendmail(sender, to_email, msg.as_string())

#         return True
#     except Exception as e:
#         print("Email sending error:", e)
#         return False

# # -------------------
# # API to resend OTP
# # -------------------
# @app.route("/resend_otp", methods=["POST"])
# def resend_otp():
#     data = request.json
#     user_id = data.get("user_id")
#     email = data.get("email")

#     user = User.query.filter_by(id=user_id, email=email).first()
#     if not user:
#         return jsonify({"status": "user_not_found"})

#     otp = str(random.randint(100000, 999999))
#     user.otp = otp
#     user.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
#     db.session.commit()

#     if send_otp_email(email, otp):
#         return jsonify({"status": "otp_sent"})
#     else:
#         return jsonify({"status": "email_failed"})

# # -------------------
# # API to verify OTP
# # -------------------
# # @app.route("/otp", methods=["GET","POST"])
# # def verify_otp():
# #     data = request.json
# #     user_id = data.get("user_id")
# #     otp_input = data.get("otp")

# #     user = User.query.filter_by(id=user_id).first()
# #     if not user:
# #         return jsonify({"status": "user_not_found"})

# #     if not user.otp or not user.otp_expiry:
# #         return jsonify({"status": "no_otp"})

# #     if datetime.utcnow() > user.otp_expiry:
# #         return jsonify({"status": "expired_otp"})

# #     if otp_input == user.otp:
# #         user.is_verified = True
# #         user.otp = None
# #         user.otp_expiry = None
# #         db.session.commit()
# #         return jsonify({"status": "verified"})

# #     return jsonify({"status": "invalid_otp"})

# # -------------------
# # Run app
# # -------------------
# @app.route("/otp", methods=["POST"])
# def verify_otp():
#     if not request.is_json:
#        # return jsonify({"status": "error", "msg": "Content-Type must be application/json"}), 415
#        return render_template('otp.html')
    
#     data = request.get_json()
#     user_id = data.get("user_id")
#     otp_input = data.get("otp")
#     # ... rest of logic
















#



 # you already imported bcrypt above

# ======================
# FORGOT PASSWORD FLOW
# ======================

@app.route("/forgot", methods=["GET"])
def forgot_page():
    return render_template("forgot.html")


@app.route("/forgot", methods=["POST"])
def forgot():
    data = request.get_json(silent=True)
    if not data or "email" not in data:
        return jsonify({"status": "error", "message": "Email required"}), 400

    email = data["email"]
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"status": "error", "message": "❌ Email not registered"}), 404

    otp = str(random.randint(100000, 999999))
    session["otp"] = otp
    session["email"] = email
    session["otp_expiry"] = (datetime.utcnow() + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")

    try:
        msg = Message(
            subject="ZestPay Password Reset",
            recipients=[email]
        )
        msg.body = f"""
Hello {user.firstName or ''},

Your OTP code is: {otp}

⚠️ Do NOT share this code with anyone.
This code expires in 5 minutes.

ZestPay Security Team
"""
        mail.send(msg)
        return jsonify({"status": "ok", "message": "✅ OTP sent to email"})
    except Exception as e:
        print("❌ Email send error:", e)
        return jsonify({"status": "error", "message": "Email send failed"}), 500


@app.route("/verify", methods=["POST"])
def verify():
    data = request.get_json(silent=True)
    if not data or "otp" not in data:
        return jsonify({"status": "error", "message": "OTP required"}), 400

    code = data["otp"]

    if "otp" not in session or "otp_expiry" not in session:
        return jsonify({"status": "error", "message": "❌ No OTP, request again"}), 400

    expiry = datetime.strptime(session["otp_expiry"], "%Y-%m-%d %H:%M:%S")
    if datetime.utcnow() > expiry:
        session.pop("otp", None)
        return jsonify({"status": "error", "message": "❌ OTP expired"}), 400

    if code == session["otp"]:
        session["otp_verified"] = True
        return jsonify({"status": "ok", "message": "✅ OTP Verified"})
    return jsonify({"status": "error", "message": "❌ Wrong OTP"}), 400


@app.route("/reset", methods=["POST"])
def reset_password():
    # Ensure OTP was verified first
    if not session.get("otp_verified"):
        return jsonify({"status": "error", "message": "OTP not verified"}), 400

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Invalid data"}), 400

    new_password = data.get("new_password")
    confirm_password = data.get("confirm_password")

    if not new_password or not confirm_password:
        return jsonify({"status": "error", "message": "Password required"}), 400

    if new_password != confirm_password:
        return jsonify({"status": "error", "message": "Passwords do not match"}), 400

    # Get the user from DB
    email = session.get("email")
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"status": "error", "message": "User not found"}), 404

    # Hash new password
    hashed_pw = bcrypt.generate_password_hash(new_password).decode("utf-8")
    user.password = hashed_pw
    db.session.commit()

    # Clear OTP session
    session.pop("otp", None)
    session.pop("otp_expiry", None)
    session.pop("otp_verified", None)

    return jsonify({"status": "ok", "message": "Password updated successfully"})













# app.py
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import time


socketio = SocketIO(app, cors_allowed_origins="*")



# ----------------
# User model
# ----------------


# ----------------
# API: Get all users
# ----------------
@app.route("/api/all_users")
def get_all_users():
    users = User.query.all()
    return jsonify({"users": [{"firstName": u.firstName} for u in users]})

# ----------------
# Emit new user on registration
# ----------------
def broadcast_new_user(first_name):
    socketio.emit("new_user_registered", {"firstName": first_name}, broadcast=True)

# Example: call this function after a new user registers
# For instance, in your register route after db.session.commit():
# broadcast_new_user(new_user.firstName)

# ----------------
# Page route
# ----------------
# @app.route("/trade")
# def trade():
#     return render_template("trade.html")  # The frontend we made earlier

# # ----------------
# # Run server

# @app.route("/api/chat_history/<receiver_email>")
# @login_required_session
# def chat_history_api(receiver_email):
#     sender_email = session['user_email']
#     messages = ChatMessage.query.filter(
#         ((ChatMessage.sender_email==sender_email) & (ChatMessage.receiver_email==receiver_email)) |
#         ((ChatMessage.sender_email==receiver_email) & (ChatMessage.receiver_email==sender_email))
#     ).order_by(ChatMessage.timestamp.asc()).all()

#     return jsonify({
#         "messages": [
#             {"sender_email": m.sender_email, "receiver_email": m.receiver_email,
#              "message": m.message, "timestamp": m.timestamp.strftime("%Y-%m-%d %H:%M:%S")}
#             for m in messages
#         ]
#     })
# @socketio.on("send_message")
# def handle_send_message(data):
#     sender = data.get("sender_email")
#     receiver = data.get("receiver_email")
#     msg_text = data.get("message")

#     if not sender or not receiver or not msg_text:
#         return

#     # Save in DB
#     chat_msg = ChatMessage(sender_email=sender, receiver_email=receiver, message=msg_text)
#     db.session.add(chat_msg)
#     db.session.commit()

#     # Emit to sender & receiver
#     emit("receive_message", {
#         "sender": sender,
#         "receiver": receiver,
#         "message": msg_text,
#         "timestamp": chat_msg.timestamp.strftime("%Y-%m-%d %H:%M:%S")
#     }, room=sender)

#     emit("receive_message", {
#         "sender": sender,
#         "receiver": receiver,
#         "message": msg_text,
#         "timestamp": chat_msg.timestamp.strftime("%Y-%m-%d %H:%M:%S")
#     }, room=receiver)

# @socketio.on("join_chat")
# def handle_join_chat(data):
#     email = data.get("email")
#     join_room(email)
# @app.route("/chat/<receiver_email>")
# @login_required_session
# def chat_page(receiver_email):
#     sender_email = session['user_email']
#     # Fetch user exists
#     receiver = User.query.filter_by(email=receiver_email).first()
#     if not receiver:
#         return "User not found", 404
#     return render_template("trade.html", sender_email=sender_email, receiver_email=receiver_email, receiver_name=receiver.firstName)


if __name__ == '__main__':

    app.run(debug=True)

 
