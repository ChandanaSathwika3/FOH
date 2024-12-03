import sqlite3
import os

def get_db_connection():
    # Connect to the database (will create if it doesn't exist)
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    # You can create tables here; for example:
    with conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                key TEXT NOT NULL,
                created_at DATETIME DEFAULT (datetime('now'))
            )
        ''')
    conn.close()

def init_dbt():
    """Initializes the database by creating the necessary tables."""
    conn = get_db_connection()
    with conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contractID TEXT NOT NULL,
                symbol TEXT NOT NULL,
                type TEXT NOT NULL,         -- Call or Put
                action TEXT NOT NULL,       -- Buy or Sell
                quantity INTEGER NOT NULL,
                price REAL NOT NULL,
                user TEXT NOT NULL,
                isactive INT NOT NULL,
                excdate DATETIME DEFAULT (datetime('now'))
            )
        ''')
    conn.close()

def init_dbw():
    """Initializes the database by creating the necessary tables."""
    conn = get_db_connection()
    with conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS wallet (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user TEXT NOT NULL,
                amount REAL NOT NULL,
                tdate DATETIME DEFAULT (datetime('now'))
            )
        ''')
    conn.close()

def create_db_if_not_exists():
    if not os.path.exists('database.db'):
        init_db()
        init_dbt()
        init_dbw()
        print("Database created.")
    else:
        print("Database already exists.")