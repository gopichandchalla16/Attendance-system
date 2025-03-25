import streamlit as st
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from mysql.connector import Error
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

# Function to establish database connection using Streamlit secrets
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

# Main application
def main():
    # Set page configuration for a professional look
    st.set_page_config(page_title="Attendance System", layout="wide", initial_sidebar_state="expanded")

    # Custom CSS for enhanced UI
    st.markdown("""
        <style>
        .main {background-color: #f0f2f6;}
        .stButton>button {background-color: #4CAF50; color: white; border-radius: 5px;}
        .stTextInput>label {font-weight: bold;}
        .stSelectbox>label {font-weight: bold;}
        .stFileUploader>label {font-weight: bold;}
        </style>
    """, unsafe_allow_html=True)

    # Sidebar navigation
    if 'user_id' not in st.session_state:
        pages = ["Login", "Register", "Forgot Password"]
    else:
        pages = ["Dashboard"]
        if st.session_state.get('is_admin', False):
            pages.append("Admin")
        pages.append("Logout")
    
    selected_page = st.sidebar.selectbox("Navigate", pages, key="nav_selectbox")

    # Page rendering based on selection
    if selected_page == "Login":
        st.header("🔑 Login")
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
        st.header("📝 Register")
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
                            sender = "your_email@gmail.com"  # Replace with your email
                            msg = MIMEText(f"Your OTP for password reset is: {otp}")
                            msg['Subject'] = "Password Reset OTP"
                            msg['From'] = sender
                            msg['To'] = email
                            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                                server.starttls()
                                server.login(sender, "your_app_password")  # Replace with your App Password
                                server.send_message(msg)
                            st.success("OTP sent to your email!")
                            st.session_state['forgot_password_step'] = 1
                        else:
                            st.error("Email not found")
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
            st.header("📊 Dashboard")
            conn = get_db_connection()
            if conn:
                try:
                    cursor = conn.cursor(dictionary=True)
                    # User details
                    cursor.execute("SELECT email, position, created_at, face_image FROM users WHERE id = %s", 
                                  (st.session_state['user_id'],))
                    user = cursor.fetchone()
                    user_face_image_base64 = base64.b64encode(user['face_image']).decode('utf-8') if user['face_image'] else None

                    # Last attendance
                    cursor.execute("SELECT login_time, logout_time FROM attendance WHERE user_id = %s ORDER BY login_time DESC LIMIT 1", 
                                  (st.session_state['user_id'],))
                    last_attendance = cursor.fetchone()

                    # 30-day attendance
                    cursor.execute("SELECT DATE(login_time) as date FROM attendance WHERE user_id = %s AND login_time >= CURDATE() - INTERVAL 30 DAY", 
                                  (st.session_state['user_id'],))
                    attendance_dates = [row['date'] for row in cursor.fetchall()]

                    # Notifications
                    cursor.execute("SELECT message, created_at FROM notifications WHERE user_id = %s AND is_read = 0 ORDER BY created_at DESC", 
                                  (st.session_state['user_id'],))
                    notifications = cursor.fetchall()

                    # Latest rota
                    cursor.execute("SELECT rota_image FROM rota ORDER BY uploaded_at DESC LIMIT 1")
                    rota = cursor.fetchone()
                    rota_image_base64 = base64.b64encode(rota['rota_image']).decode('utf-8') if rota else None

                    # Layout
                    col1, col2 = st.columns([1, 2])
                    with col1:
                        if user_face_image_base64:
                            st.image(f"data:image/jpeg;base64,{user_face_image_base64}", width=150)
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
                            status = "✅" if date in attendance_dates else "❌"
                            st.write(f"{date}: {status}")

                    # Attendance tracking
                    st.subheader("Attendance Tracking")
                    if st.session_state.get('logged_in_today', False):
                        with st.form("logout_form"):
                            logout_photo = st.file_uploader("Upload Logout Photo", type=["jpg", "png"])
                            submit_logout = st.form_submit_button("Logout")
                        if submit_logout and logout_photo:
                            process_logout(logout_photo)
                    else:
                        with st.form("login_form"):
                            login_photo = st.file_uploader("Upload Login Photo", type=["jpg", "png"])
                            submit_login = st.form_submit_button("Login")
                        if submit_login and login_photo:
                            process_login(login_photo)

                    # Notifications and Rota
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

# Helper functions for attendance tracking
def process_login(login_photo):
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT face_image FROM users WHERE id = %s", (st.session_state['user_id'],))
            user = cursor.fetchone()
            if user:
                registered_image = face_recognition.load_image_file(BytesIO(user['face_image']))
                captured_image = face_recognition.load_image_file(login_photo)
                registered_enc = face_recognition.face_encodings(registered_image)
                captured_enc = face_recognition.face_encodings(captured_image)
                if registered_enc and captured_enc and face_recognition.compare_faces([registered_enc[0]], captured_enc[0])[0]:
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
                else:
                    st.error("Face verification failed")
        finally:
            cursor.close()
            conn.close()

def process_logout(logout_photo):
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT face_image FROM users WHERE id = %s", (st.session_state['user_id'],))
            user = cursor.fetchone()
            if user:
                registered_image = face_recognition.load_image_file(BytesIO(user['face_image']))
                captured_image = face_recognition.load_image_file(logout_photo)
                registered_enc = face_recognition.face_encodings(registered_image)
                captured_enc = face_recognition.face_encodings(captured_image)
                if registered_enc and captured_enc and face_recognition.compare_faces([registered_enc[0]], captured_enc[0])[0]:
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
                else:
                    st.error("Face verification failed")
        finally:
            cursor.close()
            conn.close()

if __name__ == "__main__":
    main()
