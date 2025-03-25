import streamlit as st
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from mysql.connector import Error
import geocoder
import pandas as pd
from io import BytesIO
from datetime import datetime, timedelta
# import face_recognition  # Commented out due to installation issues
import numpy as np
import smtplib
from email.mime.text import MIMEText
import random
import base64
import os

def get_db_connection():
    try:
        conn = mysql.connector.connect(
            host=st.secrets["database"]["host"],
            user=st.secrets["database"]["user"],
            password=st.secrets["database"]["password"],
            database=st.secrets["database"]["database"]
        )
        return conn
    except Error as err:
        st.error(f"Database connection failed: {err}")
        return None

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
            st.error(f"Error initializing database: {err}")
        finally:
            cursor.close()
            conn.close()

def main():
    st.set_page_config(page_title="Attendance System", layout="wide", initial_sidebar_state="expanded")
    st.markdown("""
        <style>
        .main {background-color: #f0f2f6;}
        .stButton>button {background-color: #4CAF50; color: white; border-radius: 8px; padding: 10px;}
        .stTextInput>label, .stSelectbox>label, .stFileUploader>label {font-weight: bold; color: #333;}
        .stSidebar {background-color: #e0e7ff;}
        .stExpander {background-color: #ffffff; border-radius: 5px; padding: 10px;}
        </style>
    """, unsafe_allow_html=True)

    if 'user_id' not in st.session_state:
        pages = ["Login", "Register", "Forgot Password"]
    else:
        pages = ["Dashboard"]
        if st.session_state.get('is_admin', False):
            pages.append("Admin")
        pages.append("Logout")
    
    selected_page = st.sidebar.selectbox("Navigate", pages, key="nav_selectbox", 
                                        help="Choose a page to explore the system")

    if selected_page == "Login":
        st.header("🔑 Login to Your Account")
        with st.form("login_form"):
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            login_type = st.selectbox("Login Type", ["Employee", "Admin"])
            submit = st.form_submit_button("Login")

        if submit:
            conn = get_db_connection()
            if conn:
                try:
                    cursor = conn.cursor(dictionary=True)
                    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
                    user = cursor.fetchone()
                    if user and check_password_hash(user['password'], password):
                        st.session_state['user_id'] = user['id']
                        st.session_state['username'] = user['username']
                        st.session_state['is_admin'] = user['is_admin'] if login_type == "Admin" else False
                        st.success("Login successful!")
                        st.experimental_rerun()
                    else:
                        st.error("Invalid credentials")
                finally:
                    cursor.close()
                    conn.close()

    elif selected_page == "Register":
        st.header("📝 Register a New User")
        with st.form("register_form"):
            username = st.text_input("Username")
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            face_image = st.file_uploader("Upload Face Image", type=["jpg", "png"])
            submit = st.form_submit_button("Register")

        if submit:
            if not all([username, email, password, face_image]):
                st.error("All fields are required")
            else:
                face_image_data = face_image.read()
                conn = get_db_connection()
                if conn:
                    try:
                        cursor = conn.cursor()
                        hashed_password = generate_password_hash(password)
                        cursor.execute(
                            "INSERT INTO users (username, email, password, face_image, is_admin) VALUES (%s, %s, %s, %s, %s)",
                            (username, email, hashed_password, face_image_data, 0)
                        )
                        conn.commit()
                        st.success("Registration successful! Please login.")
                    except mysql.connector.IntegrityError:
                        st.error("Username or email already exists")
                    finally:
                        cursor.close()
                        conn.close()

    elif selected_page == "Forgot Password":
        st.header("🔒 Forgot Password")
        if 'forgot_password_step' not in st.session_state:
            st.session_state['forgot_password_step'] = 0

        if st.session_state['forgot_password_step'] == 0:
            with st.form("forgot_password_form"):
                email = st.text_input("Email")
                submit = st.form_submit_button("Send OTP")
            if submit:
                conn = get_db_connection()
                if conn:
                    try:
                        cursor = conn.cursor(dictionary=True)
                        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
                        user = cursor.fetchone()
                        if user:
                            otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
                            st.session_state['otp'] = otp
                            st.session_state['reset_email'] = email
                            sender = "afreedsk247@gmail.com"  # Replace with your email
                            msg = MIMEText(f"Your OTP for password reset is: {otp}")
                            msg['Subject'] = "Password Reset OTP"
                            msg['From'] = sender
                            msg['To'] = email
                            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                                server.starttls()
                                server.login(sender, "lcjz csqo resu uwxh")  # Replace with your App Password
                                server.send_message(msg)
                            st.success("OTP sent to your email!")
                            st.session_state['forgot_password_step'] = 1
                        else:
                            st.error("Email not found")
                    except Exception as e:
                        st.error(f"Failed to send OTP: {e}")
                    finally:
                        cursor.close()
                        conn.close()

        elif st.session_state['forgot_password_step'] == 1:
            with st.form("verify_otp_form"):
                otp_input = st.text_input("Enter OTP")
                submit = st.form_submit_button("Verify OTP")
            if submit:
                if otp_input == st.session_state['otp']:
                    st.session_state.pop('otp')
                    st.session_state['forgot_password_step'] = 2
                    st.success("OTP verified!")
                else:
                    st.error("Invalid OTP")

        elif st.session_state['forgot_password_step'] == 2:
            with st.form("reset_password_form"):
                new_password = st.text_input("New Password", type="password")
                submit = st.form_submit_button("Reset Password")
            if submit:
                conn = get_db_connection()
                if conn:
                    try:
                        cursor = conn.cursor()
                        hashed_password = generate_password_hash(new_password)
                        cursor.execute("UPDATE users SET password = %s WHERE email = %s", 
                                      (hashed_password, st.session_state['reset_email']))
                        conn.commit()
                        st.session_state.pop('reset_email')
                        st.session_state['forgot_password_step'] = 0
                        st.success("Password reset successful! Please login.")
                    finally:
                        cursor.close()
                        conn.close()

    elif selected_page == "Dashboard":
        if 'user_id' not in st.session_state:
            st.error("Please log in first")
        else:
            st.header(f"📊 Welcome, {st.session_state['username']}")
            conn = get_db_connection()
            if conn:
                try:
                    cursor = conn.cursor(dictionary=True)
                    cursor.execute("SELECT email, position, created_at, face_image FROM users WHERE id = %s", 
                                  (st.session_state['user_id'],))
                    user = cursor.fetchone()
                    user_face_image_base64 = base64.b64encode(user['face_image']).decode('utf-8') if user['face_image'] else None

                    cursor.execute("SELECT login_time, logout_time FROM attendance WHERE user_id = %s ORDER BY login_time DESC LIMIT 1", 
                                  (st.session_state['user_id'],))
                    last_attendance = cursor.fetchone()

                    cursor.execute("SELECT DATE(login_time) as date FROM attendance WHERE user_id = %s AND login_time >= CURDATE() - INTERVAL 30 DAY", 
                                  (st.session_state['user_id'],))
                    attendance_dates = [row['date'] for row in cursor.fetchall()]

                    cursor.execute("SELECT message, created_at FROM notifications WHERE user_id = %s AND is_read = 0 ORDER BY created_at DESC", 
                                  (st.session_state['user_id'],))
                    notifications = cursor.fetchall()

                    cursor.execute("SELECT rota_image FROM rota ORDER BY uploaded_at DESC LIMIT 1")
                    rota = cursor.fetchone()
                    rota_image_base64 = base64.b64encode(rota['rota_image']).decode('utf-8') if rota else None

                    col1, col2 = st.columns([1, 2])
                    with col1:
                        if user_face_image_base64:
                            st.image(f"data:image/jpeg;base64,{user_face_image_base64}", width=150, caption="Profile Photo")
                        st.write(f"**Email:** {user['email']}")
                        st.write(f"**Position:** {user['position']}")
                        st.write(f"**Joined:** {user['created_at'].strftime('%Y-%m-%d')}")

                    with col2:
                        st.subheader("Last Attendance")
                        if last_attendance:
                            st.write(f"Login: {last_attendance['login_time']}")
                            st.write(f"Logout: {last_attendance['logout_time'] or 'N/A'}")
                        else:
                            st.write("No records")

                        st.subheader("30-Day Attendance")
                        today = datetime.now().date()
                        for i in range(30):
                            date = today - timedelta(days=i)
                            status = "✅ Present" if date in attendance_dates else "❌ Absent"
                            st.write(f"{date}: {status}")

                    st.subheader("Record Attendance")
                    if st.session_state.get('logged_in_today', False):
                        with st.form("logout_form"):
                            # logout_photo = st.file_uploader("Upload Logout Photo", type=["jpg", "png"])
                            submit_logout = st.form_submit_button("Logout")  # Simplified without face recognition
                        if submit_logout:
                            process_logout(None)  # Pass None since no photo is required
                    else:
                        with st.form("login_form"):
                            # login_photo = st.file_uploader("Upload Login Photo", type=["jpg", "png"])
                            submit_login = st.form_submit_button("Login")  # Simplified without face recognition
                        if submit_login:
                            process_login(None)  # Pass None since no photo is required

                    st.subheader("Notifications")
                    for n in notifications:
                        st.info(f"{n['created_at']}: {n['message']}")
                    if rota_image_base64:
                        st.subheader("Latest Rota")
                        st.image(f"data:image/jpeg;base64,{rota_image_base64}", use_column_width=True)

                finally:
                    cursor.close()
                    conn.close()

    elif selected_page == "Admin":
        if not st.session_state.get('is_admin', False):
            st.error("Access denied")
        else:
            st.header("🛠️ Admin Panel")
            admin_options = ["View Attendance", "Manage Users", "Upload Rota", "Send Notification"]
            selected_option = st.sidebar.selectbox("Admin Options", admin_options)

            if selected_option == "View Attendance":
                view = st.selectbox("Select View", ["Daily", "Weekly", "Monthly", "Yearly"])
                search_query = st.text_input("Search by Username")
                conn = get_db_connection()
                if conn:
                    try:
                        cursor = conn.cursor(dictionary=True)
                        query = {
                            "Daily": "DATE(a.login_time) = CURDATE()",
                            "Weekly": "WEEK(a.login_time) = WEEK(CURDATE())",
                            "Monthly": "MONTH(a.login_time) = MONTH(CURDATE())",
                            "Yearly": "YEAR(a.login_time) = YEAR(CURDATE())"
                        }[view]
                        sql = f"""
                            SELECT u.username, a.login_time, a.logout_time
                            FROM users u LEFT JOIN attendance a ON u.id = a.user_id
                            WHERE {query}
                        """
                        if search_query:
                            sql += f" AND u.username LIKE '%{search_query}%'"
                        cursor.execute(sql)
                        df = pd.DataFrame(cursor.fetchall())
                        st.dataframe(df)
                    finally:
                        cursor.close()
                        conn.close()

            elif selected_option == "Manage Users":
                conn = get_db_connection()
                if conn:
                    try:
                        cursor = conn.cursor(dictionary=True)
                        cursor.execute("SELECT id, username, email, position FROM users WHERE is_admin = 0")
                        users = cursor.fetchall()
                        for user in users:
                            with st.expander(f"{user['username']} ({user['email']})"):
                                with st.form(f"update_{user['id']}"):
                                    new_username = st.text_input("Username", user['username'])
                                    new_email = st.text_input("Email", user['email'])
                                    new_position = st.text_input("Position", user['position'])
                                    submit = st.form_submit_button("Update")
                                    if submit:
                                        cursor.execute("UPDATE users SET username = %s, email = %s, position = %s WHERE id = %s",
                                                      (new_username, new_email, new_position, user['id']))
                                        conn.commit()
                                        st.success("User updated")
                    finally:
                        cursor.close()
                        conn.close()

            elif selected_option == "Upload Rota":
                st.subheader("Upload Rota")
                rota_image = st.file_uploader("Upload Rota Image", type=["jpg", "png"])
                if st.button("Upload"):
                    if rota_image:
                        conn = get_db_connection()
                        if conn:
                            try:
                                cursor = conn.cursor()
                                cursor.execute("INSERT INTO rota (rota_image) VALUES (%s)", (rota_image.read(),))
                                conn.commit()
                                st.success("Rota uploaded")
                            finally:
                                cursor.close()
                                conn.close()

            elif selected_option == "Send Notification":
                st.subheader("Send Notification")
                message = st.text_area("Message")
                if st.button("Send"):
                    conn = get_db_connection()
                    if conn:
                        try:
                            cursor = conn.cursor()
                            cursor.execute("SELECT id FROM users WHERE is_admin = 0")
                            users = cursor.fetchall()
                            for user in users:
                                cursor.execute("INSERT INTO notifications (message, user_id) VALUES (%s, %s)", 
                                              (message, user['id']))
                            conn.commit()
                            st.success("Notification sent")
                        finally:
                            cursor.close()
                            conn.close()

    elif selected_page == "Logout":
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.success("Logged out successfully")
        st.experimental_rerun()

def process_login(login_photo):
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            # Simplified: No face recognition, just record login time and location
            login_time = datetime.now()
            g = geocoder.ip('me')
            latitude, longitude = g.latlng if g.latlng else (0.0, 0.0)
            cursor.execute("""
                INSERT INTO attendance (user_id, login_time, login_latitude, login_longitude) 
                VALUES (%s, %s, %s, %s)
            """, (st.session_state['user_id'], login_time, latitude, longitude))
            conn.commit()
            st.session_state['logged_in_today'] = True
            st.success("Login recorded")
        finally:
            cursor.close()
            conn.close()

def process_logout(logout_photo):
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            # Simplified: No face recognition, just record logout time and location
            logout_time = datetime.now()
            g = geocoder.ip('me')
            latitude, longitude = g.latlng if g.latlng else (0.0, 0.0)
            cursor.execute("""
                UPDATE attendance 
                SET logout_time = %s, logout_latitude = %s, logout_longitude = %s 
                WHERE user_id = %s AND logout_time IS NULL 
                ORDER BY login_time DESC LIMIT 1
            """, (logout_time, latitude, longitude, st.session_state['user_id']))
            conn.commit()
            st.session_state['logged_in_today'] = False
            st.success("Logout recorded")
        finally:
            cursor.close()
            conn.close()

if __name__ == "__main__":
    init_db()
    main()
