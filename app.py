import face_recognition
import cv2
import re
import numpy as np
from flask import Flask, render_template, request, redirect, session, flash, jsonify, url_for
import MySQLdb
from werkzeug.utils import secure_filename
import os
import json
from flask_bcrypt import check_password_hash
from werkzeug.security import generate_password_hash, check_password_hash
import dlib
import subprocess
from datetime import datetime, timedelta
import time
import json


db = MySQLdb.connect(host='', user='', password='', database='')
cursor = db.cursor()

app = Flask(__name__)
app.secret_key = 'your_secret_key'

detector = dlib.get_frontal_face_detector()
predictor = dlib.shape_predictor("shape_predictor_68_face_landmarks.dat") 
face_rec_model = dlib.face_recognition_model_v1("dlib_face_recognition_resnet_model_v1.dat") 

UPLOAD_FOLDER = 'static/uploads/'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.permanent_session_lifetime = timedelta(hours=6)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

login_attempts = {}

MAX_LOGIN_ATTEMPTS = 5

LOCKOUT_DURATION = 300  # 5 minutes

@app.route('/', methods=['GET'])
def index():
    # ตรวจสอบว่าผู้ใช้เป็นสมาชิกหรือไม่
    if 'username' in session:
        return redirect('/dashboard')
    else:
        return redirect('/login')
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        ip_address = request.remote_addr
        if ip_address in login_attempts and login_attempts[ip_address]['attempts'] >= MAX_LOGIN_ATTEMPTS:
            if time.time() - login_attempts[ip_address]['timestamp'] < LOCKOUT_DURATION:
                flash('Too many login attempts. Please try again later.', 'danger')
                return render_template('login.html')
        # ตรวจสอบข้อมูลผู้ใช้ในฐานข้อมูล
        cursor = db.cursor()
        query = "SELECT * FROM users WHERE username=%s"
        cursor.execute(query, (username,))
        user = cursor.fetchone()

        if user is None:
            flash('Invalid username or password.', 'danger')
            return render_template('login.html')
        elif not check_password_hash(user[2], password):
            flash("Incorrect Password.", 'danger')
            # Increment login attempts and track timestamp
            if ip_address not in login_attempts:
                login_attempts[ip_address] = {'attempts': 1, 'timestamp': time.time()}
            else:
                login_attempts[ip_address]['attempts'] += 1
            return render_template('login.html')
        else:
            if ip_address in login_attempts:
                del login_attempts[ip_address]
            session.permanent = True
            session['username'] = username
            unlock_client(ip_address)
            # บันทึกเหตุการณ์การเข้าใช้งานผู้ใช้ในฐานข้อมูล
            event_cursor = db.cursor()
            eve_query = "INSERT INTO events (user_id,username_event, event_type) VALUES (%s, %s, %s)"
            event_cursor.execute(eve_query, (user[0], username, 'login'))
            db.commit()
            return redirect('/dashboard')
    else:
        return render_template('login.html')
    
    
@app.route('/faceid', methods=['POST'])
def faceid():
    faceIdUser = request.form['faceIdUser']
    photo = request.files['photo']
    
    ip_address = request.remote_addr
    if faceIdUser and photo:
        login_filename = os.path.join(UPLOAD_FOLDER, 'facelogin.jpg')
        photo.save(login_filename)
        
        old_user = face_recognition.load_image_file(os.path.join(UPLOAD_FOLDER, f"{faceIdUser}.jpg"))
        old_encode = face_recognition.face_encodings(old_user)[0]

        image = cv2.imread(login_filename)
        face_detect = detect_face_dlib(image)
        if face_detect is not None:
            new_user = face_recognition.load_image_file(login_filename)
            new_encode = face_recognition.face_encodings(new_user)[0]

            results = face_recognition.compare_faces([old_encode], new_encode)

            if any(results):
                # Faces match, proceed to login
                cursor = db.cursor()
                query = "SELECT * FROM users WHERE username=%s"
                cursor.execute(query, (faceIdUser,))
                user = cursor.fetchone()

                if user is not None:
                    session.permanent = True
                    session['username'] = faceIdUser
                    unlock_client(ip_address)

                    event_cursor = db.cursor()
                    eve_query = "INSERT INTO events (user_id,username_event, event_type) VALUES (%s, %s, %s)"
                    event_cursor.execute(eve_query, (user[0], faceIdUser, 'login'))
                    db.commit()
                    
                    return redirect('/dashboard')
                else:
                    flash('User not found.', 'danger')
        else:
            flash('FaceID failed', 'danger')

    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        file = request.files['file']
        check_query = "SELECT * FROM users WHERE username=%s OR email=%s"
        cursor.execute(check_query, (username, email))
        existing_user = cursor.fetchone()

        hashed_password = generate_password_hash(password)

        if 'file' not in request.files:
            flash('Please upload your face...', 'danger')
            return render_template('register.html')
        if existing_user:
            flash('Username or email already exists.', 'danger')
            return render_template('register.html')
    
        if file and allowed_file(file.filename):
            file_extension = os.path.splitext(file.filename)[1]
            filename = secure_filename(file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], username + file_extension)
            file.save(image_path)
            
            image = cv2.imread(image_path)
            face_rect = detect_face_dlib(image)
            if face_rect is not None:
                face_embedding = encode_face_dlib(image, face_rect)
                if face_embedding is not None:
                    sql = "INSERT INTO users (username, password, email, image_path, face_encoding) VALUES (%s, %s, %s, %s, %s)"
                    values = (username, hashed_password, email, image_path, json.dumps(face_embedding.tolist()))
                    cursor.execute(sql, values)
                    db.commit()

                    flash('Successfully!!!', 'success')
                    return render_template('register.html')
                else:
                    flash('Face encoding failed!!!', 'danger')
                    return render_template('register.html')
            else:
                flash('Face detection failed!!!', 'danger')
                return render_template('register.html')
            
    return render_template('register.html')

def detect_face_dlib(image):
    rects = detector(image, 1)
    if len(rects) != 1: 
        return None
    return rects[0]  

def encode_face_dlib(image, rect):
    shape = predictor(image, rect)
    face_descriptor = face_rec_model.compute_face_descriptor(image, shape)
    return np.array(face_descriptor)


def unlock_client(ip_address):
    try:
        subprocess.check_call(['sudo', 'iptables', '-I', 'FORWARD', '-i', 'ens37', '-o', 'ens33', '-s', ip_address, '-j', 'ACCEPT'])
        subprocess.check_call(['sudo', 'iptables-save'])
        
        return True
    except subprocess.CalledProcessError:
        return False

def lock_client(ip_address):
    try:
        subprocess.check_call(['sudo', 'iptables', '-D', 'FORWARD', '-i', 'ens37', '-o', 'ens33', '-s', ip_address, '-j', 'ACCEPT'])
        subprocess.check_call(['sudo', 'iptables-save'])
        return True
    except subprocess.CalledProcessError:
        return False
    
@app.route('/dashboard', methods=['GET'])
def dashboard():
    # ตรวจสอบว่า session ได้หมดเวลาหรือยัง
    if '_permanent' not in session:
        flash('Your session has expired. Please log in again.', 'danger')
        return redirect('/login')

    # ตรวจสอบว่าผู้ใช้เข้าสู่ระบบหรือไม่
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    else:
        return redirect('/login')

ipv4_pattern = re.compile(r'^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.'
                          r'(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.'
                          r'(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.'
                          r'(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$')

@app.route('/dhcpconfiger', methods=['GET', 'POST'])
def dhcp_configuration():
    if 'username' in session and get_user_role(session['username']) == 'admin':

        if request.method == 'POST':
            try:
                # รับข้อมูลจากฟอร์ม
                your_domain = request.form.get('your_domain', '')
                range_start = request.form.get('range_start', '')
                range_end = request.form.get('range_end', '')
                subnet = request.form.get('subnet', '')
                ipsubnet = request.form.get('ipsubnet', '')
                netmask = request.form.get('netmask', '')
                default_lease_time = request.form.get('default_lease_time', '')
                max_lease_time = request.form.get('max_lease_time', '')
            except Exception as e:
                flash(f'Error while getting form data: {str(e)}', 'danger')
                return render_template('dhcpconfiger.html')

            # ตรวจสอบ IP address ให้ถูกต้องตามรูปแบบของ IPv4
            try:
                for ip in [range_start, range_end, subnet, ipsubnet, netmask]:
                    if not ipv4_pattern.match(ip):
                        flash(f'{ip} is not a valid IPv4 address.', 'danger')
                        return render_template('dhcpconfiger.html')
            except Exception as e:
                flash(f'Error validating IP addresses: {str(e)}', 'danger')
                return render_template('dhcpconfiger.html')

            # Update dhcpd.conf data
            dhcpd_config_data = f'''option domain-name "{your_domain}";
    subnet {subnet} netmask {netmask} {{
        range {range_start} {range_end};
        option routers 192.168.1.10;
        option domain-name-servers {ipsubnet}, 8.8.4.4;
        default-lease-time {default_lease_time};
        max-lease-time {max_lease_time};
    }}'''
            # Write to the DHCP config file
            try:
                sudo_command = ['sudo', 'tee', '/etc/dhcp/dhcpd.conf']
                subprocess.run(sudo_command, input=dhcpd_config_data, text=True, check=True)
            except Exception as e:
                flash(f'Error : {str(e)}', 'danger')
                return render_template('dhcpconfiger.html')

            # Restart the DHCP server
            try:
                stop_command = ['sudo', 'systemctl', 'stop', 'isc-dhcp-server']
                start_command = ['sudo', 'systemctl', 'start', 'isc-dhcp-server']
                subprocess.run(stop_command, check=True)
                subprocess.run(start_command, check=True)
            except Exception as e:
                flash(f'Error while restarting DHCP server: {str(e)}', 'danger')
                return render_template('dhcpconfiger.html')

            flash('DHCP configuration updated successfully!', 'success')
            return "DHCP configuration updated successfully"
        
        return render_template('dhcpconfiger.html')
    else:
        flash('Access denied!!!', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/logout', methods=['GET'])
def logout():
    ip_address = request.remote_addr
    lock_client(ip_address)
    if 'username' in session:
        # ดึงชื่อผู้ใช้จากเซสชัน
        username = session['username']

        # ดึงข้อมูลผู้ใช้จากฐานข้อมูล
        cursor = db.cursor()
        query = "SELECT * FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        user = cursor.fetchone()

        if user:
            # บันทึกเหตุการณ์การออกจากระบบในฐานข้อมูล
            event_cursor = db.cursor()
            event_query = "INSERT INTO events (user_id, username_event, event_type) VALUES (%s, %s, %s)"
            event_cursor.execute(event_query, (user[0], username, 'logout'))
            db.commit()

        # ล้างข้อมูลเซสชัน
        session.pop('username', None)

    return redirect('/login')

@app.route('/events')
def events():
    if 'username' in session and get_user_role(session['username']) == 'admin':
        query = "SELECT * FROM events ORDER BY event_date DESC"
        cursor.execute(query)
        events = cursor.fetchall()
        # ส่งข้อมูล events ไปยัง template events.html เพื่อแสดงผล
        return render_template('events.html', events=events)
    else:
        flash('Access denied!!!', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/tables')
def tables():
    if 'username' in session and get_user_role(session['username']) == 'admin':
        query = "SELECT * FROM users"
        cursor.execute(query)
        tableusers = cursor.fetchall()

        return render_template('tables.html', tableusers=tableusers)
    else:
        flash('Access denied!!!', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/get_user/<int:user_id>')
def get_user(user_id):
    # ดึงข้อมูลผู้ใช้จากฐานข้อมูลตาม user_id
    query = "SELECT username FROM users WHERE id = %s"
    cursor.execute(query, (user_id,))
    user_data = cursor.fetchone()

    # ส่งข้อมูลกลับในรูปแบบ JSON
    return jsonify({'username': user_data[0]})

@app.route('/update_user', methods=['POST'])
def update_user():
    update_user_id = request.form['updateUserId']
    update_password = request.form['updatePassword']
    update_email = request.form['updateEmail']
    update_role = request.form['updateRole']
    update_file = request.files['updateFile']

    check_query = "SELECT * FROM users WHERE id=%s"
    cursor.execute(check_query, (update_user_id,))
    existing_user = cursor.fetchone()

    query = "SELECT username FROM users WHERE id = %s"
    cursor.execute(query, (update_user_id,))
    result = cursor.fetchone()

    if result:
        username = result[0]

    if not existing_user:
        flash('User not found.', 'danger')
        return redirect(url_for('tables'))
  # Replace with your actual template name

    check_query = "SELECT * FROM users WHERE (email=%s) AND id != %s"
    cursor.execute(check_query, (update_email, update_user_id))
    duplicate_user = cursor.fetchone()

    if duplicate_user:
        flash('Email already exists.', 'danger')
        return redirect(url_for('tables'))
  # Replace with your actual template name

    # Update user information
    update_query = "UPDATE users SET email=%s, role=%s WHERE id=%s"
    update_values = (update_email, update_role, update_user_id)
    cursor.execute(update_query, update_values)

    # Update password if provided
    if update_password:
        hashed_password = generate_password_hash(update_password)
        update_password_query = "UPDATE users SET password=%s WHERE id=%s"
        cursor.execute(update_password_query, (hashed_password, update_user_id))

    # Update profile image if provided
    if 'updateFile' in request.files:
        if update_file and allowed_file(update_file.filename):
            file_extension = os.path.splitext(update_file.filename)[1]
            filename = secure_filename(update_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], username + file_extension)
            update_file.save(image_path)

            image = cv2.imread(image_path)
            face_rect = detect_face_dlib(image)
            if face_rect is not None:
                face_embedding = encode_face_dlib(image, face_rect)
                if face_embedding is not None:
                    update_image_query = "UPDATE users SET image_path=%s, face_encoding=%s WHERE id=%s"
                    update_image_values = (image_path, json.dumps(face_embedding.tolist()), update_user_id)
                    cursor.execute(update_image_query, update_image_values)
                    db.commit()
                    flash('Successfully updated user information!', 'success')
                    return redirect(url_for('tables'))
                else:
                    flash('Face encoding failed!!!', 'danger')
                    return redirect(url_for('tables'))
            else:
                flash('Face detection failed!!!', 'danger')
                return redirect(url_for('tables'))
            
    db.commit()
    flash('Successfully updated user information!', 'success')
    return redirect(url_for('tables'))

def get_user_role(username):
    query = "SELECT role FROM users WHERE username = %s"
    cursor.execute(query, (username,))
    result = cursor.fetchone()
    if result:
        return result[0]
    else:
        return None

if __name__ == '__main__':
    app.run(host='192.168.1.10', port=80)
