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
                username TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                created_at DATETIME DEFAULT (datetime('now'))
            )
        ''')
    conn.close()

def create_db_if_not_exists():
    if not os.path.exists('database.db'):
        init_db()
        print("Database created.")
    else:
        print("Database already exists.")
