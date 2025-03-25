from flask import Flask, request, render_template, jsonify, session, redirect, url_for, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from mysql.connector import pooling, Error
import os
import geocoder
import pandas as pd
from io import BytesIO
from datetime import datetime, timedelta
import face_recognition
import numpy as np
import smtplib
from email.mime.text import MIMEText
import random
import base64

app = Flask(__name__)
app.secret_key = os.urandom(24)

# MySQL Connection Pooling
db_config = {
    "host": "localhost",
    "user": "root",
    "password": "Afreedsk@247",  # Replace with your MySQL password
    "database": "gps_face_db",
    "pool_name": "mypool",
    "pool_size": 5
}

try:
    connection_pool = mysql.connector.pooling.MySQLConnectionPool(**db_config)
except Error as err:
    print(f"Error creating connection pool: {err}")

def get_db_connection():
    try:
        return connection_pool.get_connection()
    except Error as err:
        print(f"Database connection failed: {err}")
        flash(f"Database connection failed: {err}", "error")
        return None

# Database initialization
def init_db():
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) UNIQUE,
                    email VARCHAR(100) UNIQUE,
                    password VARCHAR(255),
                    face_image LONGBLOB,
                    position VARCHAR(100) DEFAULT 'Employee',
                    is_admin BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS attendance (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT,
                    login_time DATETIME,
                    logout_time DATETIME,
                    login_photo_path VARCHAR(255),
                    logout_photo_path VARCHAR(255),
                    login_latitude FLOAT,
                    login_longitude FLOAT,
                    logout_latitude FLOAT,
                    logout_longitude FLOAT,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS rota (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    rota_image LONGBLOB,
                    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS notifications (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    message TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_read BOOLEAN DEFAULT 0,
                    user_id INT,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)
            conn.commit()
        except Error as err:
            print(f"Error initializing database: {err}")
        finally:
            cursor.close()
            conn.close()

# Jinja2 custom filters
app.jinja_env.filters['strptime'] = lambda s, fmt: datetime.strptime(s, fmt)
app.jinja_env.filters['strftime'] = lambda dt, fmt: dt.strftime(fmt) if dt else 'N/A'

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/check_admin', methods=['POST'])
def check_admin():
    email = request.json.get('email')
    conn = get_db_connection()
    if not conn:
        return jsonify({"is_admin": False})
    try:
        cursor = conn.cursor(dictionary=True, buffered=True)
        cursor.execute("SELECT is_admin FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        return jsonify({"is_admin": user['is_admin'] if user else False})
    finally:
        cursor.close()
        conn.close()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        login_type = request.form.get('login_type')

        conn = get_db_connection()
        if not conn:
            return render_template('login.html')
        try:
            cursor = conn.cursor(dictionary=True, buffered=True)
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['is_admin'] = user['is_admin'] if login_type == 'admin' else False
                flash("Login successful!", "success")
                return redirect(url_for('admin' if session['is_admin'] else 'dashboard'))
            else:
                flash("Invalid credentials", "error")
        finally:
            cursor.close()
            conn.close()
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        face_image = request.files.get('face_image')

        if not all([username, email, password, face_image]):
            flash("All fields are required", "error")
            return render_template('register.html')

        face_image_data = face_image.read()

        conn = get_db_connection()
        if not conn:
            return render_template('register.html')
        
        try:
            cursor = conn.cursor(buffered=True)
            hashed_password = generate_password_hash(password)
            cursor.execute(
                "INSERT INTO users (username, email, password, face_image, is_admin) VALUES (%s, %s, %s, %s, %s)",
                (username, email, hashed_password, face_image_data, 0)
            )
            conn.commit()
            flash("Registration successful! Please login.", "success")
            return redirect(url_for('login'))
        except mysql.connector.IntegrityError:
            flash("Username or email already exists", "error")
        finally:
            cursor.close()
            conn.close()
    return render_template('register.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        conn = get_db_connection()
        if not conn:
            return render_template('forgot_password.html')
        try:
            cursor = conn.cursor(dictionary=True, buffered=True)
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
            if user:
                otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
                session['otp'] = otp
                session['reset_email'] = email
                session['otp_sent'] = True

                sender = "afreedsk247@gmail.com"  # Replace with your email
                msg = MIMEText(f"Dear User,\n\nYour OTP for password reset is: {otp}\nPlease use this to reset your password within 10 minutes.\n\nRegards,\nAttendance System Team")
                msg['Subject'] = "Password Reset OTP"
                msg['From'] = sender
                msg['To'] = email

                try:
                    with smtplib.SMTP('smtp.gmail.com', 587) as server:
                        server.starttls()
                        server.login(sender, "lcjz csqo resu uwxh")  # Replace with your App Password
                        server.send_message(msg)
                    flash("OTP sent to your email!", "success")
                except Exception as e:
                    flash(f"An error occurred while sending OTP: {str(e)}", "error")
                return redirect(url_for('forgot_password'))
            else:
                flash("Email not found", "error")
        finally:
            cursor.close()
            conn.close()
    return render_template('forgot_password.html')

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    otp = request.form.get('otp')
    if otp == session.get('otp'):
        session.pop('otp')
        session['otp_verified'] = True
        flash("OTP verified!", "success")
        return redirect(url_for('reset_password'))
    else:
        flash("Invalid OTP", "error")
        return redirect(url_for('forgot_password'))

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if not session.get('otp_verified'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        conn = get_db_connection()
        if not conn:
            return render_template('reset_password.html')
        try:
            cursor = conn.cursor(buffered=True)
            hashed_password = generate_password_hash(new_password)
            cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_password, session['reset_email']))
            conn.commit()
            session.pop('reset_email')
            session.pop('otp_verified')
            session.pop('otp_sent')
            flash("Password reset successful! Please login.", "success")
            return redirect(url_for('login'))
        finally:
            cursor.close()
            conn.close()
    return render_template('reset_password.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session or session.get('is_admin'):
        flash("Access denied", "error")
        return redirect(url_for('login'))

    conn = get_db_connection()
    if not conn:
        return render_template('dashboard.html', last_login=None, last_logout=None, rota_image_base64=None)

    cursor = conn.cursor(dictionary=True, buffered=True)
    try:
        # Fetch user details
        cursor.execute("SELECT email, face_image, position, created_at FROM users WHERE id = %s", (session['user_id'],))
        user = cursor.fetchone()
        if not user:
            flash("User not found", "error")
            return redirect(url_for('logout'))

        # Check today's attendance
        cursor.execute("SELECT login_time, logout_time FROM attendance WHERE user_id = %s AND DATE(login_time) = CURDATE()", (session['user_id'],))
        today_attendance = cursor.fetchone()
        can_login = not bool(today_attendance and today_attendance['logout_time'])
        attendance_submitted = bool(today_attendance)

        # Fetch last attendance record
        cursor.execute("""
            SELECT login_time, logout_time 
            FROM attendance 
            WHERE user_id = %s 
            ORDER BY login_time DESC 
            LIMIT 1
        """, (session['user_id'],))
        last_attendance = cursor.fetchone()

        # Fetch 30-day attendance summary
        cursor.execute("""
            SELECT DATE(login_time) as date, COUNT(*) as present 
            FROM attendance 
            WHERE user_id = %s 
            GROUP BY DATE(login_time)
        """, (session['user_id'],))
        attendance_data = cursor.fetchall()
        attendance_records = []
        for i in range(30):
            date = (datetime.now() - timedelta(days=i)).date()
            present = any(record['date'] == date for record in attendance_data)
            attendance_records.append({'date': date, 'present': present})

        # Fetch unread notifications
        cursor.execute("SELECT message, created_at FROM notifications WHERE user_id = %s AND is_read = 0 ORDER BY created_at DESC", (session['user_id'],))
        notifications = cursor.fetchall()

        # Fetch latest rota
        cursor.execute("SELECT rota_image FROM rota ORDER BY uploaded_at DESC LIMIT 1")
        rota = cursor.fetchone()
        rota_image_base64 = base64.b64encode(rota['rota_image']).decode('utf-8') if rota and rota['rota_image'] else None

        # Convert face image to base64
        user_face_image_base64 = base64.b64encode(user['face_image']).decode('utf-8') if user['face_image'] else None

        return render_template('dashboard.html',
                              user_email=user['email'],
                              user_face_image_base64=user_face_image_base64,
                              user_position=user['position'],
                              created_at=user['created_at'],
                              last_login=last_attendance['login_time'] if last_attendance else None,
                              last_logout=last_attendance['logout_time'] if last_attendance else None,
                              can_login=can_login,
                              attendance_submitted=attendance_submitted,
                              attendance_records=attendance_records,
                              notifications=notifications,
                              rota_image_base64=rota_image_base64)
    except Error as err:
        print(f"Error in dashboard: {err}")
        flash(f"Database error: {err}", "error")
        return render_template('dashboard.html', last_login=None, last_logout=None, rota_image_base64=None)
    finally:
        cursor.close()
        conn.close()

@app.route('/login_photo', methods=['POST'])
def login_photo():
    if 'user_id' not in session:
        return jsonify({"success": False, "message": "Not logged in"})

    file = request.files.get('face_image')
    if not file:
        return jsonify({"success": False, "message": "No photo uploaded"})

    conn = get_db_connection()
    if not conn:
        return jsonify({"success": False, "message": "Database error"})

    cursor = conn.cursor(dictionary=True, buffered=True)
    try:
        cursor.execute("SELECT face_image FROM users WHERE id = %s", (session['user_id'],))
        user = cursor.fetchone()

        if not user['face_image']:
            return jsonify({"success": False, "message": "User face image not found"})

        registered_image = face_recognition.load_image_file(BytesIO(user['face_image']))
        captured_image = face_recognition.load_image_file(file)
        registered_enc = face_recognition.face_encodings(registered_image)
        captured_enc = face_recognition.face_encodings(captured_image)

        if not registered_enc or not captured_enc or not face_recognition.compare_faces([registered_enc[0]], captured_enc[0])[0]:
            return jsonify({"success": False, "message": "Face verification failed"})

        uploads_dir = os.path.join(app.static_folder, 'uploads')
        login_time = datetime.now()
        login_photo_path = os.path.join(uploads_dir, f"{session['username']}_login_{login_time.strftime('%Y%m%d%H%M%S')}.jpg")
        file.save(login_photo_path)

        g = geocoder.ip('me')
        latitude, longitude = g.latlng if g.latlng else (0.0, 0.0)

        cursor.execute("""
            INSERT INTO attendance (user_id, login_time, login_photo_path, login_latitude, login_longitude) 
            VALUES (%s, %s, %s, %s, %s)
        """, (session['user_id'], login_time, login_photo_path, latitude, longitude))
        conn.commit()

        return jsonify({"success": True, "message": "Login recorded"})
    except Exception as e:
        print(f"Error in login_photo: {e}")
        return jsonify({"success": False, "message": f"Server error: {str(e)}"})
    finally:
        cursor.close()
        conn.close()

@app.route('/logout_photo', methods=['POST'])
def logout_photo():
    if 'user_id' not in session:
        return jsonify({"success": False, "message": "Not logged in"})

    file = request.files.get('face_image')
    if not file:
        return jsonify({"success": False, "message": "No photo uploaded"})

    conn = get_db_connection()
    if not conn:
        return jsonify({"success": False, "message": "Database error"})

    cursor = conn.cursor(dictionary=True, buffered=True)
    try:
        cursor.execute("SELECT face_image FROM users WHERE id = %s", (session['user_id'],))
        user = cursor.fetchone()

        if not user['face_image']:
            return jsonify({"success": False, "message": "User face image not found"})

        registered_image = face_recognition.load_image_file(BytesIO(user['face_image']))
        captured_image = face_recognition.load_image_file(file)
        registered_enc = face_recognition.face_encodings(registered_image)
        captured_enc = face_recognition.face_encodings(captured_image)

        if not registered_enc or not captured_enc or not face_recognition.compare_faces([registered_enc[0]], captured_enc[0])[0]:
            return jsonify({"success": False, "message": "Face verification failed"})

        uploads_dir = os.path.join(app.static_folder, 'uploads')
        logout_time = datetime.now()
        logout_photo_path = os.path.join(uploads_dir, f"{session['username']}_logout_{logout_time.strftime('%Y%m%d%H%M%S')}.jpg")
        file.save(logout_photo_path)

        g = geocoder.ip('me')
        latitude, longitude = g.latlng if g.latlng else (0.0, 0.0)

        cursor.execute("""
            UPDATE attendance 
            SET logout_time = %s, logout_photo_path = %s, logout_latitude = %s, logout_longitude = %s 
            WHERE user_id = %s AND logout_time IS NULL 
            ORDER BY login_time DESC 
            LIMIT 1
        """, (logout_time, logout_photo_path, latitude, longitude, session['user_id']))
        conn.commit()

        return jsonify({"success": True, "message": "Logout recorded"})
    except Exception as e:
        print(f"Error in logout_photo: {e}")
        return jsonify({"success": False, "message": f"Server error: {str(e)}"})
    finally:
        cursor.close()
        conn.close()

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return jsonify({"success": False, "message": "Not logged in"})

    username = request.form.get('username')
    email = request.form.get('email')
    face_image = request.files.get('face_image')
    position = request.form.get('position')

    conn = get_db_connection()
    if not conn:
        return jsonify({"success": False, "message": "Database error"})
    cursor = conn.cursor(buffered=True)
    try:
        updates = []
        params = []
        if username:
            updates.append("username = %s")
            params.append(username)
            session['username'] = username
        if email:
            updates.append("email = %s")
            params.append(email)
        if position:
            updates.append("position = %s")
            params.append(position)
        if face_image:
            face_image_data = face_image.read()
            updates.append("face_image = %s")
            params.append(face_image_data)

        if updates:
            params.append(session['user_id'])
            query = f"UPDATE users SET {', '.join(updates)} WHERE id = %s"
            cursor.execute(query, tuple(params))
            conn.commit()
            
            return jsonify({"success": True, "message": "Profile updated"})
        return jsonify({"success": False, "message": "No changes provided"})
    except mysql.connector.IntegrityError:
        return jsonify({"success": False, "message": "Username or email already exists"})
    finally:
        cursor.close()
        conn.close()

@app.route('/admin_update_user/<int:user_id>', methods=['POST'])
def admin_update_user(user_id):
    if not session.get('is_admin'):
        return jsonify({"success": False, "message": "Access denied"})

    username = request.form.get('username')
    email = request.form.get('email')
    position = request.form.get('position')
    face_image = request.files.get('face_image')

    conn = get_db_connection()
    if not conn:
        return jsonify({"success": False, "message": "Database error"})
    cursor = conn.cursor(buffered=True)
    try:
        updates = []
        params = []
        if username:
            updates.append("username = %s")
            params.append(username)
        if email:
            updates.append("email = %s")
            params.append(email)
        if position:
            updates.append("position = %s")
            params.append(position)
        if face_image:
            face_image_data = face_image.read()
            updates.append("face_image = %s")
            params.append(face_image_data)

        if updates:
            params.append(user_id)
            query = f"UPDATE users SET {', '.join(updates)} WHERE id = %s"
            cursor.execute(query, tuple(params))
            conn.commit()

            return jsonify({"success": True, "message": "User updated"})
        return jsonify({"success": False, "message": "No changes provided"})
    except mysql.connector.IntegrityError:
        return jsonify({"success": False, "message": "Username or email already exists"})
    finally:
        cursor.close()
        conn.close()

@app.route('/upload_rota', methods=['POST'])
def upload_rota():
    if not session.get('is_admin'):
        return jsonify({"success": False, "message": "Access denied"})

    file = request.files.get('rota_image')
    if not file:
        return jsonify({"success": False, "message": "No file uploaded"})

    rota_image_data = file.read()

    conn = get_db_connection()
    if not conn:
        return jsonify({"success": False, "message": "Database error"})
    cursor = conn.cursor(buffered=True)
    try:
        cursor.execute("INSERT INTO rota (rota_image) VALUES (%s)", (rota_image_data,))
        conn.commit()
        return jsonify({"success": True, "message": "Rota uploaded successfully"})
    except Error as err:
        return jsonify({"success": False, "message": f"Error uploading rota: {str(err)}"})
    finally:
        cursor.close()
        conn.close()

@app.route('/send_notification', methods=['POST'])
def send_notification():
    if not session.get('is_admin'):
        return jsonify({"success": False, "message": "Access denied"}), 403

    message = request.form.get('message')
    if not message:
        return jsonify({"success": False, "message": "No message provided"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"success": False, "message": "Database connection failed"}), 500

    cursor = conn.cursor(dictionary=True, buffered=True)
    try:
        cursor.execute("SELECT id FROM users WHERE is_admin = 0")
        users = cursor.fetchall()
        if not users:
            return jsonify({"success": False, "message": "No users found to notify"}), 404

        for user in users:
            cursor.execute("INSERT INTO notifications (message, user_id) VALUES (%s, %s)", (message, user['id']))
        conn.commit()
        return jsonify({"success": True, "message": "Notification sent to all users"}), 200
    except Error as err:
        print(f"Database error: {err}")
        return jsonify({"success": False, "message": f"Database error: {str(err)}"}), 500
    except Exception as e:
        print(f"Unexpected error: {e}")
        return jsonify({"success": False, "message": f"Unexpected error: {str(e)}"}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/check_notifications')
def check_notifications():
    if 'user_id' not in session or session.get('is_admin'):
        return jsonify({"success": False, "message": ""})

    conn = get_db_connection()
    if not conn:
        return jsonify({"success": False, "message": "Database error"})

    cursor = conn.cursor(dictionary=True, buffered=True)
    try:
        cursor.execute("""
            SELECT message 
            FROM notifications 
            WHERE user_id = %s AND is_read = 0 
            ORDER BY created_at DESC 
            LIMIT 1
        """, (session['user_id'],))
        notification = cursor.fetchone()
        if notification:
            cursor.execute("UPDATE notifications SET is_read = 1 WHERE user_id = %s AND message = %s", (session['user_id'], notification['message']))
            conn.commit()
            return jsonify({"success": True, "message": notification['message']})
        return jsonify({"success": False, "message": ""})
    except Error as err:
        print(f"Error checking notifications: {err}")
        return jsonify({"success": False, "message": "Server error"})
    finally:
        cursor.close()
        conn.close()

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully", "success")
    return redirect(url_for('login'))

@app.route('/admin')
def admin():
    if not session.get('is_admin'):
        flash("Access denied", "error")
        return redirect(url_for('login'))

    view = request.args.get('view', 'daily')
    search_query = request.args.get('search', '')

    conn = get_db_connection()
    if not conn:
        return render_template('admin.html', data=[], view=view, admin_profile=None, users=[], all_attendance=[], rota_image_base64=None)

    cursor = conn.cursor(dictionary=True, buffered=True)
    try:
        # Fetch admin profile
        cursor.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
        admin_profile = cursor.fetchone()
        admin_profile['face_image_base64'] = base64.b64encode(admin_profile['face_image']).decode('utf-8') if admin_profile['face_image'] else None

        # Fetch all users
        cursor.execute("SELECT id, username, email, position, face_image FROM users WHERE is_admin = 0")
        users_raw = cursor.fetchall()
        users = []
        for user in users_raw:
            user['face_image_base64'] = base64.b64encode(user['face_image']).decode('utf-8') if user['face_image'] else None
            users.append(user)

        # Fetch attendance data based on view
        if view == 'daily':
            query = """
                SELECT u.username, u.position, a.user_id, a.login_time, a.logout_time, 
                       a.login_photo_path, a.logout_photo_path, a.login_latitude, a.login_longitude,
                       a.logout_latitude, a.logout_longitude,
                       TIMESTAMPDIFF(SECOND, a.login_time, COALESCE(a.logout_time, NOW())) as seconds_worked
                FROM users u LEFT JOIN attendance a ON u.id = a.user_id
                WHERE DATE(a.login_time) = CURDATE()
                ORDER BY a.login_time DESC
            """
        elif view == 'weekly':
            query = """
                SELECT u.username, u.position, a.user_id, a.login_time, a.logout_time, 
                       a.login_photo_path, a.logout_photo_path, a.login_latitude, a.login_longitude,
                       a.logout_latitude, a.logout_longitude,
                       TIMESTAMPDIFF(SECOND, a.login_time, COALESCE(a.logout_time, NOW())) as seconds_worked
                FROM users u LEFT JOIN attendance a ON u.id = a.user_id
                WHERE WEEK(a.login_time) = WEEK(CURDATE())
                ORDER BY a.login_time DESC
            """
        elif view == 'monthly':
            query = """
                SELECT u.username, u.position, a.user_id, a.login_time, a.logout_time, 
                       a.login_photo_path, a.logout_photo_path, a.login_latitude, a.login_longitude,
                       a.logout_latitude, a.logout_longitude,
                       TIMESTAMPDIFF(SECOND, a.login_time, COALESCE(a.logout_time, NOW())) as seconds_worked
                FROM users u LEFT JOIN attendance a ON u.id = a.user_id
                WHERE MONTH(a.login_time) = MONTH(CURDATE())
                ORDER BY a.login_time DESC
            """
        else:  # yearly
            query = """
                SELECT u.username, u.position, a.user_id, a.login_time, a.logout_time, 
                       a.login_photo_path, a.logout_photo_path, a.login_latitude, a.login_longitude,
                       a.logout_latitude, a.logout_longitude,
                       TIMESTAMPDIFF(SECOND, a.login_time, COALESCE(a.logout_time, NOW())) as seconds_worked
                FROM users u LEFT JOIN attendance a ON u.id = a.user_id
                WHERE YEAR(a.login_time) = YEAR(CURDATE())
                ORDER BY a.login_time DESC
            """
        cursor.execute(query)
        data = cursor.fetchall()

        for record in data:
            record['login_photo_exists'] = record['login_photo_path'] and os.path.exists(record['login_photo_path'])
            record['logout_photo_exists'] = record['logout_photo_path'] and os.path.exists(record['logout_photo_path'])
            if record['seconds_worked']:
                hours = record['seconds_worked'] // 3600
                minutes = (record['seconds_worked'] % 3600) // 60
                seconds = record['seconds_worked'] % 60
                record['hours_worked'] = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
                record['color'] = 'red' if hours < 9 else 'green'
            else:
                record['hours_worked'] = "N/A"
                record['color'] = 'black'

        # Fetch all attendance for search
        if search_query:
            cursor.execute("""
                SELECT u.username, u.position, a.user_id, a.login_time, a.logout_time, 
                       a.login_photo_path, a.logout_photo_path, a.login_latitude, a.login_longitude,
                       a.logout_latitude, a.logout_longitude,
                       TIMESTAMPDIFF(SECOND, a.login_time, COALESCE(a.logout_time, NOW())) as seconds_worked
                FROM users u LEFT JOIN attendance a ON u.id = a.user_id
                WHERE u.username LIKE %s
                ORDER BY a.login_time DESC
            """, (f"%{search_query}%",))
        else:
            cursor.execute("""
                SELECT u.username, u.position, a.user_id, a.login_time, a.logout_time, 
                       a.login_photo_path, a.logout_photo_path, a.login_latitude, a.login_longitude,
                       a.logout_latitude, a.logout_longitude,
                       TIMESTAMPDIFF(SECOND, a.login_time, COALESCE(a.logout_time, NOW())) as seconds_worked
                FROM users u LEFT JOIN attendance a ON u.id = a.user_id
                ORDER BY a.login_time DESC
            """)
        all_attendance = cursor.fetchall()

        for record in all_attendance:
            record['login_photo_exists'] = record['login_photo_path'] and os.path.exists(record['login_photo_path'])
            record['logout_photo_exists'] = record['logout_photo_path'] and os.path.exists(record['logout_photo_path'])
            if record['seconds_worked']:
                hours = record['seconds_worked'] // 3600
                minutes = (record['seconds_worked'] % 3600) // 60
                seconds = record['seconds_worked'] % 60
                record['hours_worked'] = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
                record['color'] = 'red' if hours < 9 else 'green'
            else:
                record['hours_worked'] = "N/A"
                record['color'] = 'black'

        # Fetch latest rota
        cursor.execute("SELECT rota_image FROM rota ORDER BY uploaded_at DESC LIMIT 1")
        rota = cursor.fetchone()
        rota_image_base64 = base64.b64encode(rota['rota_image']).decode('utf-8') if rota and rota['rota_image'] else None

        return render_template('admin.html', data=data, view=view, admin_profile=admin_profile, users=users, all_attendance=all_attendance, search_query=search_query, rota_image_base64=rota_image_base64)
    finally:
        cursor.close()
        conn.close()

@app.route('/view_excel')
def view_excel():
    if not session.get('is_admin'):
        return redirect(url_for('login'))

    conn = get_db_connection()
    if not conn:
        return render_template('view_excel.html', table="")

    cursor = conn.cursor(dictionary=True, buffered=True)
    try:
        cursor.execute("""
            SELECT u.username, a.login_time, a.logout_time, a.login_photo_path, a.logout_photo_path
            FROM users u LEFT JOIN attendance a ON u.id = a.user_id
        """)
        df = pd.DataFrame(cursor.fetchall())
        df['hours_worked'] = df.apply(
            lambda row: (row['logout_time'] or datetime.now()) - row['login_time'] if row['login_time'] else None, axis=1
        )
        html_table = df.to_html(index=False, classes='table table-striped')
        return render_template('view_excel.html', table=html_table)
    finally:
        cursor.close()
        conn.close()

@app.route('/export')
def export():
    if not session.get('is_admin'):
        return redirect(url_for('login'))

    conn = get_db_connection()
    if not conn:
        return jsonify({"success": False, "message": "Database error"})

    cursor = conn.cursor(dictionary=True, buffered=True)
    try:
        cursor.execute("""
            SELECT u.username, a.login_time, a.logout_time, a.login_photo_path, a.logout_photo_path
            FROM users u LEFT JOIN attendance a ON u.id = a.user_id
        """)
        df = pd.DataFrame(cursor.fetchall())
        df['hours_worked'] = df.apply(
            lambda row: (row['logout_time'] or datetime.now()) - row['login_time'] if row['login_time'] else None, axis=1
        )
        output = BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df.to_excel(writer, sheet_name='Attendance', index=False)
        output.seek(0)
        return send_file(output, download_name='attendance.xlsx', as_attachment=True)
    finally:
        cursor.close()
        conn.close()

if __name__ == '__main__':
    uploads_dir = os.path.join(app.static_folder, 'uploads')
    os.makedirs(uploads_dir, exist_ok=True)
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)