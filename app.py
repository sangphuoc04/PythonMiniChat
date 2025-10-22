# app.py
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient, DESCENDING
from datetime import timedelta, datetime
from flask_paginate import Pagination, get_page_args


import os

app = Flask(__name__)
# Generate a secure random secret key if it doesn't exist
if not os.path.exists('.secret_key'):
    with open('.secret_key', 'wb') as f:
        f.write(os.urandom(32))

# Load the secret key
with open('.secret_key', 'rb') as f:
    app.secret_key = f.read()

app.permanent_session_lifetime = timedelta(days=1)


MONGO_URI = "mongodb://localhost:27017/"
client = MongoClient(MONGO_URI)
db = client['PythonMiniWebApp']
users_col = db['users']
messages_col = db['messages']

def current_user():
    return session.get('username')

def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            flash("Bạn cần đăng nhập để truy cập.", "warning")
            return redirect(url_for('login'))
        return fn(*args, **kwargs)
    return wrapper

@app.route('/')
def index():
    if current_user():
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        confirm = request.form.get('confirm_password','')

  
        if not username or not password or not confirm:
            flash("Vui lòng điền đầy đủ thông tin.", "danger")
            return render_template('register.html')
        if len(password) < 6:
            flash("Mật khẩu phải có ít nhất 6 ký tự.", "danger")
            return render_template('register.html')
        if password != confirm:
            flash("Mật khẩu và xác nhận không khớp.", "danger")
            return render_template('register.html')

        if users_col.find_one({"username": username}):
            flash("Tên người dùng đã tồn tại. Vui lòng chọn tên khác.", "danger")
            return render_template('register.html')

        # Generate password hash with stronger parameters
        pw_hash = generate_password_hash(password, method='pbkdf2:sha256:260000')
        users_col.insert_one({
            "username": username,
            "password_hash": pw_hash,
            "created_at": datetime.utcnow()
        })
        flash("Đăng ký thành công! Bạn có thể đăng nhập.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')

        user = users_col.find_one({"username": username})
        if not user:
            flash("Tài khoản không tồn tại.", "danger")
            return render_template('login.html')
        if not check_password_hash(user['password_hash'], password):
            flash("Sai mật khẩu.", "danger")
            return render_template('login.html')

        session.permanent = True
        session['username'] = username
        flash("Đăng nhập thành công.", "success")
        return redirect(url_for('chat'))

    return render_template('login.html')

# Logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("Bạn đã đăng xuất.", "info")
    return redirect(url_for('login'))


@app.route('/chat', methods=['GET', 'POST'])
@login_required
def chat():
    if request.method == 'POST':
        text = request.form.get('text','').strip()
        if not text:
            flash("Không được gửi tin nhắn rỗng.", "danger")
            return redirect(url_for('chat'))
        if len(text) > 280:
            flash("Tin nhắn tối đa 280 ký tự.", "danger")
            return redirect(url_for('chat'))

        messages_col.insert_one({
            "username": current_user(),
            "text": text,
            "created_at": datetime.utcnow()
        })
        return redirect(url_for('chat'))

  
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    if per_page is None or per_page <= 0:
        per_page = 10
    total = messages_col.count_documents({})
    cursor = messages_col.find().sort("created_at", -1).skip(offset).limit(per_page)  # -1 for DESCENDING to get newest first

    messages = []
    for m in cursor:
        created_at = m.get("created_at")
        if created_at:
            # Format timestamp to local Vietnam time
            created_at = created_at + timedelta(hours=7)  # UTC+7
        messages.append({
            "username": m.get("username"),
            "text": m.get("text"),
            "created_at": created_at
        })
    # pagination object for template
    pagination = Pagination(page=page, per_page=per_page, total=total, record_name='messages', css_framework='bootstrap4')
    return render_template('chat.html', messages=messages, pagination=pagination)

# User profile (bonus)
@app.route('/profile/<username>')
@login_required
def profile(username):
    user = users_col.find_one({"username": username}, {"password_hash": 0})
    if not user:
        flash("Không tìm thấy người dùng.", "warning")
        return redirect(url_for('chat'))
    # count user's messages
    msg_count = messages_col.count_documents({"username": username})
    return render_template('profile.html', user=user, msg_count=msg_count)

# Optional API to fetch latest messages (for ajax)
@app.route('/api/messages/latest')
@login_required
def api_latest_messages():
    limit = int(request.args.get('limit', 20))
    docs = messages_col.find().sort("created_at", DESCENDING).limit(limit)
    out = []
    for m in docs:
        out.append({
            "username": m.get("username"),
            "text": m.get("text"),
            "created_at": m.get("created_at").isoformat() if m.get("created_at") else None
        })
    return jsonify(out)

# ---------- Run ----------
if __name__ == '__main__':
    app.run(debug=True)
    print("Databases:", client.list_database_names())

