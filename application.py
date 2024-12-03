from flask import Flask, render_template,jsonify
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

app = Flask(__name__)
app.secret_key = 'your_secret_key'

app.config['MAIL_SERVER'] = 'smtp.gmail.com'            # Your SMTP server
app.config['MAIL_PORT'] = 587                           # Common port for TLS
app.config['MAIL_USE_TLS'] = True                       # Use TLS for security
app.config['MAIL_USERNAME'] = 'chandanasatwika@gmail.com'    # Your email address
app.config['MAIL_PASSWORD'] = 'nbjlnyqkjtkshalx'           # Your email password
app.config['MAIL_DEFAULT_SENDER'] = ('chandana', 'chandanasatwika@gmail.com')
app.config['MAIL_MAX_EMAILS'] = 50                      

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

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    user = conn.execute('SELECT * FROM users WHERE id= ?', (user_id,)).fetchone()
    conn.execute('DELETE FROM transactions WHERE user = ?', (user,))
    conn.execute('DELETE FROM wallet WHERE user = ?', (user,))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_dashboard'))


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
        key = Fernet.generate_key()
        cipher_suite = Fernet(key)
        # Hash the password for security
        hashed_password = cipher_suite.encrypt(password.encode())

        # Save to SQLite database
        try:
            conn = get_db_connection()
            conn.execute(
                'INSERT INTO users (username, email, password,key) VALUES (?, ?, ?,?)',
                (username, email, hashed_password,key)
            )
            conn.commit()
            conn.close()
            flash("Registration successful!", "success")
            subject = "Welcome to FOX OF HOOD!"
            body = """
Hello {username},

Thank you for registering with FOX OF HOOD! We're excited to have you on board. Here are a few things you can do with your account:

- Explore our stock portfolio simulation tools.
- Keep track of your trades and manage your assets.
- Access reports and insights.

If you have any questions, feel free to reach out to our support team.

Best regards,  
The FOX OF HOOD Team
"""
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
        cipher_suite = Fernet(user['key'])
        passw=cipher_suite.decrypt(user['password']).decode()
        #passw=cipher_suite.decrypt(user['password']).decode()
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
        print(user['password'])
        #cipher_suite.encrypt(password.encode())
        cipher_suite = Fernet(user['key'])
        passw=cipher_suite.decrypt(user['password']).decode()
        print(passw)
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
        wallet_entry = conn.execute(
        '''
        SELECT amount FROM wallet WHERE user = ?
        ''', (username,)
    ).fetchone()
        
        wallet_amount = wallet_entry['amount'] if wallet_entry else 0
        wallet_amount = round(wallet_amount, 2)
        conn.close()
        
        if user:
            email = user['email']  # Adjust based on your actual table structure
            return render_template('profile.html', username=username, email=email,wallet_amount=wallet_amount)
        else:
            flash("User not found!", "danger")
            return redirect(url_for('login'))
    else:
        flash("You need to log in first!", "danger")
        return redirect(url_for('login'))

@app.route('/add_amount', methods=['POST'])
def add_amount():
    # Get the username from session
    username = session.get('username')
    if not username:
        return redirect(url_for('homeuser'))
    
    # Get the amount from the form
    amount_to_add = request.form.get('amount', type=int)
    
    # Update the wallet in the database
    conn = get_db_connection()
    wallet_entry = conn.execute(
        '''
        SELECT amount FROM wallet WHERE user = ?
        ''', (username,)
    ).fetchone()
    
    if wallet_entry:
        # Update existing wallet amount
        new_amount = wallet_entry['amount'] + amount_to_add
        conn.execute(
            '''
            UPDATE wallet SET amount = ? WHERE user = ?
            ''', (new_amount, username)
        )
    else:
        # Insert a new wallet entry
        conn.execute(
            '''
            INSERT INTO wallet (user, amount) VALUES (?, ?)
            ''', (username, amount_to_add)
        )
    conn.commit()
    conn.close()
    
    return redirect(url_for('profile'))


# Function to fetch Top Gainers and Losers
def fetch_stock_data():
    api_key = 'demo'  # Replace with your API key
    url = 'https://www.alphavantage.co/query'
    # URL for fetching Top Gainers and Losers
    stock_data_url = f'{url}?function=TOP_GAINERS_LOSERS&apikey={api_key}'

    try:
        # Make the API request
        response = requests.get(stock_data_url)
        data = response.json()  # Convert the response to JSON

        # Extract the data for top gainers and losers from the response
        # Assuming the structure of the response contains 'top_gainers' and 'top_losers' keys
        top_gainers = data.get('top_gainers', [])
        top_losers = data.get('top_losers', [])
        most_actively_traded= data.get('most_actively_traded', [])

        return {
            'top_gainers': top_gainers,
            'top_losers': top_losers,
            'most_actively_traded':most_actively_traded
        }
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data: {e}")
        return {
            'top_gainers': [],
            'top_losers': [],
            'most_actively_traded':[]
        }

@app.route('/report')
def report():
    stock_data = fetch_stock_data()
    return render_template('report.html', 
                           top_gainers=stock_data['top_gainers'], 
                           top_losers=stock_data['top_losers'],
                           most_actively_traded=stock_data['most_actively_traded'])

# Fetch options data
def fetch_options_data(search):
    api_key = "demo"  # Replace with your actual API key
    url = f'https://www.alphavantage.co/query?function=HISTORICAL_OPTIONS&symbol={search}&apikey={api_key}'
    response = requests.get(url)
    return response.json().get("data", [])

@app.route('/transaction', methods=['POST'])
def transaction():
    """Handles transaction creation and updates the user's wallet."""
    data = request.json
    if 'username' in session:
        username = session['username']
    else:
        return jsonify({"error": "User not logged in"}), 401
    print(username)

    # Validate input data
    required_fields = ['contractID', 'symbol', 'type', 'action', 'quantity', 'price']
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing fields in request"}), 400

    try:
        # Fetch user's current wallet balance
        conn = get_db_connection()
        user_balance = conn.execute(
            'SELECT amount FROM wallet WHERE user = ?', (username,)
        ).fetchone()
        
        if user_balance is None:
            return jsonify({"error": "User not found"}), 404

        balance = user_balance['amount']
        print(f"Current wallet for {username}: {balance}")

        # Calculate the total amount involved in the transaction
        total_amount = float(data['quantity']) * float(data['price'])

        if data['action'].lower() == 'buy':
            # Deduct amount for 'buy' action
            ask_price = float(data['price'])  # Assuming price is the ask price
            if balance < total_amount:
                return jsonify({"error": "Insufficient funds"}), 400
            # Deduct from wallet
            new_balance = balance - total_amount
            conn.execute(
                'UPDATE wallet SET amount = ? WHERE user = ?',
                (new_balance, username)
            )

            # Insert transaction as active for 'buy' action
            conn.execute(
                '''
                INSERT INTO transactions (contractID, symbol, type, action, quantity, price, user, isactive)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (data['contractID'], data['symbol'], data['type'], data['action'], data['quantity'], data['price'], username, 1)
            )

        elif data['action'].lower() == 'sell':
            # Check if user has an active contract (isactive = 1) for the contract they want to sell
            active_contract = conn.execute(
                'SELECT id, quantity FROM transactions WHERE user = ? AND contractID = ? AND isactive = 1',
                (username, data['contractID'])
            ).fetchone()

            if active_contract is None or active_contract['quantity'] < data['quantity']:
                return jsonify({"error": "Not enough active contracts to sell"}), 400

            # Add amount for 'sell' action
            bid_price = float(data['price'])  # Assuming price is the bid price
            new_balance = balance + total_amount
            conn.execute(
                'UPDATE wallet SET amount = ? WHERE user = ?',
                (new_balance, username)
            )

            # Mark the sold contract as inactive and adjust quantity
            new_quantity = active_contract['quantity'] - data['quantity']
            if new_quantity == 0:
                conn.execute(
                    'UPDATE transactions SET isactive = 0 WHERE id = ?',
                    (active_contract['id'],)
                )
            else:
                conn.execute(
                    'UPDATE transactions SET quantity = ?, isactive = 1 WHERE id = ?',
                    (new_quantity, active_contract['id'])
                )

            # Insert the new sell transaction with isactive = 0
            conn.execute(
                '''
                INSERT INTO transactions (contractID, symbol, type, action, quantity, price, user, isactive)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (data['contractID'], data['symbol'], data['type'], data['action'], data['quantity'], data['price'], username, 0)
            )

        else:
            return jsonify({"error": "Invalid action. Use 'buy' or 'sell'"}), 400

        conn.commit()
        conn.close()

        return jsonify({"message": "Transaction successful"}), 201
    except Exception as e:
        return jsonify({"error": f"An error occurred: {e}"}), 500


@app.route('/transactions', methods=['GET'])
def get_transactions():
    """Fetches all transactions from the SQLite database."""
    try:
        conn = get_db_connection()
        transactions = conn.execute('SELECT * FROM transactions').fetchall()
        conn.close()

        # Format transactions into a JSON-friendly list
        result = [
            {
                "id": row[0],
                "contractID": row[1],
                "symbol": row[2],
                "type": row[3],
                "action": row[4],
                "quantity": row[5],
                "price": row[6],
            }
            for row in transactions
        ]
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": f"An error occurred: {e}"}), 500

@app.route('/history')
def history():
    if 'username' in session:
        username = session['username']  # Get the logged-in username from the session
        
        # Connect to the database
        conn = get_db_connection()
        
        # Fetch transactions for the specific user
        transactions = conn.execute(
            'SELECT * FROM transactions WHERE user = ?',
            (username,)
        ).fetchall()
        
        conn.close()

        # Render the template with the fetched transaction data
        return render_template('history.html', transactions=transactions)
    else:
        # Redirect to login or handle unauthorized access
        return redirect(url_for('login'))



@app.route('/trade',methods=['GET'])
def trade():
    search = request.args.get('search', '').strip().upper()
    options = fetch_options_data(search)
    #print(options)
    return render_template("trade.html",options=options)

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