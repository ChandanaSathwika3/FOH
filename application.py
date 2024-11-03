from flask import Flask, render_template
import yfinance as yf
import os
from yahooquery import Screener
from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash
import random
import string
from database import create_db_if_not_exists,get_db_connection
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
from flask_mail import Mail, Message
from cryptography.fernet import Fernet
import requests
# Generate a key (store it securely and reuse it for encrypting/decrypting)
key = Fernet.generate_key()
cipher_suite = Fernet(key)


app = Flask(__name__)
app.secret_key = 'your_secret_key'

app.config['MAIL_SERVER'] = 'smtp.gmail.com'            # Your SMTP server
app.config['MAIL_PORT'] = 587                           # Common port for TLS
app.config['MAIL_USE_TLS'] = True                       # Use TLS for security
app.config['MAIL_USERNAME'] = 'chandanasathwika@gmail.com'    # Your email address
app.config['MAIL_PASSWORD'] = 'nbjlnyqkjtkshalx'           # Your email password
app.config['MAIL_DEFAULT_SENDER'] = ('Chandana', 'chandanasathwika@gmail.com')
app.config['MAIL_MAX_EMAILS'] = 50                      # Optional, sets a limit for batch emails

# Initialize Mail extension
mail = Mail(app)

# Helper function to generate a random CAPTCHA
def generate_captcha():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=6))

def send_email(subject, recipient, body):
    try:
        msg = Message(subject, recipients=[recipient])
        msg.body = body
        mail.send(msg)
        return "Email sent successfully"
    except Exception as e:
        print(f"Failed to send email: {e}")
        return "Failed to send email"


# Dummy admin credentials (replace with your own secure method, like a database)
ADMIN_CREDENTIALS = {
    'email': 'admin@gmail.com',
    'password': 'admin'
}

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/admin')
def admin():
    return render_template('admin.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if email == ADMIN_CREDENTIALS['email'] and password == ADMIN_CREDENTIALS['password']:
            flash("Login successful!", "success")
            return redirect(url_for('admin_dashboard'))
        else:
            flash("Invalid credentials. Please try again.", "danger")
    
    return render_template('admin_login.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    # Connect to the SQLite database
    conn = get_db_connection()
    
    # Fetch user details from the users table
    users = conn.execute('SELECT id, username, email, created_at FROM users').fetchall()
    
    # Close the database connection
    conn.close()
    
    # Render the admin dashboard template and pass the user details
    return render_template('admin_dashboard.html', users=users)



@app.route('/registerpage')
def registerpage():
    return render_template("register.html", methods=['POST'])

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        cpassword = request.form.get('cpassword')
        captcha_input = request.form.get('captcha')
        captcha_generated = session.get('captcha')
        print(f"Username: {username}")
        print(f"Email: {email}")
        print(f"Password: {password}")
        print(f"Confirm Password: {cpassword}")
        print(f"CAPTCHA Input: {captcha_input}")
        print(f"CAPTCHA Generated: {captcha_generated}")
        # Server-side validation
        if password != cpassword:
            flash("Passwords do not match.", "error")
            return redirect(url_for('register'))
        
        if captcha_input != captcha_generated:
            flash("Invalid CAPTCHA. Please try again.", "error")
            return redirect(url_for('register'))

        # Hash the password for security
        hashed_password = cipher_suite.encrypt(password.encode())

        # Save to SQLite database
        try:
            conn = get_db_connection()
            conn.execute(
                'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                (username, email, hashed_password)
            )
            conn.commit()
            conn.close()
            conn = get_db_connection()
            user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            conn.close()
            flash("Registration successful!", "success")
            subject = "Welcome to FOX OF HOOD!"
            body = f" Hello {user['username']},\nThank you for registering with FOX OF HOOD! We're excited to have you on board. Here are a few things you can do with your account:\n- Explore our stock portfolio simulation tools.\n- Keep track of your trades and manage your assets.\n- Access reports and insights.\nIf you have any questions, feel free to reach out to our support team.\n\nBest regards,  \nThe FOX OF HOOD Team"
            send_email(subject, email, body)
            return redirect(url_for('home'))
        except sqlite3.IntegrityError:
            flash("Email already exists. Please use a different email.", "error")
            return redirect(url_for('register'))
        finally:
            conn.close()

    # Generate a new CAPTCHA for each registration attempt
    session['captcha'] = generate_captcha()
    return render_template('register.html', captcha=session['captcha'])

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        
        # Connect to the database and fetch user details
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        passw=cipher_suite.decrypt(user['password']).decode()
        if user:
            # Prepare email details
            subject = "FOX OF HOOD! User Account Recovery"
            body = f"Hello {user['username']},\n\nYour login details are:\nUsername: {user['username']}\nPassword: {passw}\n\nThank you for being part of FOX OF HOOD!"
            
            # Send the email
            send_email(subject, email, body)
            
            flash("A recovery email has been sent to your email address.", "success")
        else:
            flash("Email address not found. Please check and try again.", "error")
        
        return redirect(url_for('login'))
    
    return render_template("forgot_password.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        print(username,password)
        # Fetch the user from the database
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        passw=cipher_suite.decrypt(user['password']).decode()
        if user and passw== password:
            session['username'] = user['username']  # Store username in session
            flash("Login successful!", "success")
            return redirect(url_for('homeuser'))  # Redirect to home page after successful login
        else:
            flash("Invalid username or password!", "danger")

    return render_template('login.html')

@app.route('/homeuser')
def homeuser():
    return render_template('index.html')

@app.route('/profile')
def profile():
    if 'username' in session:
        username = session['username']
        
        # Fetch user data from the database
        conn = get_db_connection()  # Assuming you have a function to get DB connection
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user:
            email = user['email']  # Adjust based on your actual table structure
            return render_template('profile.html', username=username, email=email)
        else:
            flash("User not found!", "danger")
            return redirect(url_for('login'))
    else:
        flash("You need to log in first!", "danger")
        return redirect(url_for('login'))



@app.route('/report')
def report():
    # Make a request to Alpha Vantage API
    api_key = 'E9GL742F46VKCLNV'  # Replace with your API key
    url = 'https://www.alphavantage.co/query'
    params = {
        'function': 'NEWS_SENTIMENT',
        'tickers': 'AAPL',
        'apikey': api_key
    }
    
    response = requests.get(url, params=params)
    data = response.json()

    # Check if data retrieval was successful
    if "feed" in data:
        articles = data["feed"]
    else:
        articles = []

    return render_template('report.html', articles=articles)

@app.route('/trade')
def trade():
    return render_template("trade.html",)

# Log route
@app.route('/log')
def log():
    return render_template("log.html")

@app.route('/logout')
def logout():
    # Clear the session
    session.pop('username', None)  # Remove the username from the session
    session.clear()  # Clear all session data (optional)

    # Redirect to the home page
    return redirect(url_for('home'))

if __name__ == "__main__":
    create_db_if_not_exists()
    app.run(debug=True)



