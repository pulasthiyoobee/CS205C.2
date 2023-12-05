import requests
from flask import Flask, render_template, request, redirect, url_for, session
from zapv2 import ZAPv2
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import pycountry
import time

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a secure secret key

# SQLite database setup
DATABASE = 'ud.db'

# Create a table for users if not exists
def create_table():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

create_table()

# Route for home page
@app.route('/')
def home():
    if 'username' in session:
        return render_template('index.html', username=session['username'])
    return redirect(url_for('login'))

# Route for login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username=?', (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session['username'] = username
            return redirect(url_for('home'))
        else:
            return render_template('index.html', error='Invalid username or password')

    return render_template('index.html')

# Route for registration page
@app.route('/register', methods=['GET', 'POST'])
def register():
    # Fetch the list of countries
    countries = list(pycountry.countries)

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the username already exists
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username=?', (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            conn.close()
            return render_template('register.html', error='Username already exists. Choose a different one.', countries=countries)

        # If the username is unique, hash the password and insert the user into the database
        hashed_password = generate_password_hash(password)
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        conn.close()

        return redirect(url_for('login'))

    return render_template('register.html', countries=countries)

def perform_scan(target_url):
    api_key = 'sd8p3p6vn07icelk90h58rvijn'  # Replace with your ZAP API key

    # Create ZAP object with proper proxy settings
    zap = ZAPv2(apikey=api_key, proxies={'http': 'http://localhost:8080', 'https': 'http://localhost:8080'})

    # Start the ZAP spider
    zap_spider_id = zap.spider.scan(target_url)

    # Poll the progress until the spider is complete
    while int(zap.spider.status(zap_spider_id)) < 100:
        print(f'Spider progress: {zap.spider.status(zap_spider_id)}%')
        time.sleep(2)

    print('Spider completed. Starting scanning...')

    # Start the ZAP active scanner
    zap_scan_id = zap.ascan.scan(target_url, apikey=api_key)

    # Poll the progress until the scan is complete
    while int(zap.ascan.status(zap_scan_id)) < 100:
        print(f'Scan progress: {zap.ascan.status(zap_scan_id)}%')
        time.sleep(2)

    print('Scan completed.')

    # Get and return the alerts
    alerts = zap.core.alerts(baseurl=target_url)
    return alerts, zap_scan_id

# Route for conducting a vulnerability scan
@app.route('/scan', methods=['POST'])
def scan():
    target_website = request.form.get('targetWebsite')

    if not target_website:
        return render_template('scan_results.html', error='Please enter a target website.', username=session['username'])

    # Perform a security scan using OWASP ZAP
    vulnerabilities, zap_scan_id = perform_scan(target_website)

    return render_template('scan_results.html', target_website=target_website, vulnerabilities=vulnerabilities, username=session['username'])

# Route for logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/about')
def about():
    if 'username' in session:
        return render_template('about.html', username=session['username'])
    return render_template('about.html')

@app.route('/account')
def account():
    if 'username' in session:
        # Fetch user details from the database (modify as needed)
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username=?', (session['username'],))
        user_details = cursor.fetchone()
        conn.close()

        if user_details:
            # Convert the user_details tuple to a dictionary for easy access in the template
            user_details_dict = {
                'id': user_details[0],
                'username': user_details[1],
                'email': user_details[2],
                'full_name': user_details[3],
                'country': user_details[4],
                # Add more fields as needed
            }

            return render_template('account.html', user_details=user_details_dict, username=session['username'])
        else:
            return render_template('account.html', user_details=None, username=session['username'])
    else:
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
