import sqlite3
import os
import jwt
import random
import string
from datetime import datetime, timedelta
from Crypto.Hash import SHA256

DB_NAME = "users.db"
SECRET_KEY = "SuperSecretKey123"  # Change this to a strong secret key

def create_db():
    """Creates the database if it doesn't exist"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        )
    """)

    # User data table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            data_key TEXT NOT NULL,
            data_value TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    conn.commit()
    conn.close()

def hash_password(password: str, salt: str) -> str:
    """Generates a SHA-256 hash of the password using the given salt"""
    hasher = SHA256.new()
    hasher.update((password + salt).encode())
    return hasher.hexdigest()

def add_user(username: str, password: str, is_admin=False):
    """Adds a new user to the database with hashed password and salt"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    salt = os.urandom(16).hex()  # Generate a random salt
    password_hash = hash_password(password, salt)

    try:
        cursor.execute("""
            INSERT INTO users (username, password_hash, salt, is_admin) 
            VALUES (?, ?, ?, ?)
        """, (username, password_hash, salt, int(is_admin)))
        conn.commit()
    except sqlite3.IntegrityError:
        print(f"⚠️ Username {username} already exists.")
    
    conn.close()

def authenticate_user(username, password):
    """Authenticates a user and returns True if credentials are valid"""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row  # Enables dictionary-like row access
    cursor = conn.cursor()

    cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    conn.close()
    if user:
        stored_hash, salt = user["password_hash"], user["salt"]
        return hash_password(password, salt) == stored_hash
    return False

def create_jwt(username, is_admin):
    """Creates a JWT token for the authenticated user"""
    expiration = datetime.utcnow() + timedelta(hours=1)  # Token expires in 1 hour
    payload = {
        "username": username,
        "is_admin": is_admin,
        "exp": expiration
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token

def verify_jwt(token):
    """Verifies the JWT token and returns the payload if valid"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], options={"require": ["exp"]})
        return payload
    except jwt.ExpiredSignatureError:
        print("⚠️ Token has expired.")
    except jwt.InvalidTokenError:
        print("⚠️ Invalid token.")
    return None

def generate_data_key():
    """Generates a unique key for user data based on timestamp + random characters"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")  # YYYYMMDD_HHMMSS
    random_suffix = ''.join(random.choices(string.ascii_letters + string.digits, k=4))  # 4 random chars
    return f"{timestamp}_{random_suffix}"

def add_user_data(username, value):
    """Adds specific data for a user with an auto-generated unique key"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if user:
        user_id = user[0]
        data_key = generate_data_key()  # Generate unique key
        cursor.execute("""
            INSERT INTO user_data (user_id, data_key, data_value) 
            VALUES (?, ?, ?)
        """, (user_id, data_key, value))
        conn.commit()
        print(f"✅ Added data '{data_key}: {value}' for user {username}.")
    else:
        print(f"⚠️ User {username} not found.")

    conn.close()


def get_user_data(username):
    """Retrieves all stored data for a specific user"""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT data_key, data_value FROM user_data 
        JOIN users ON user_data.user_id = users.id 
        WHERE users.username = ?
    """, (username,))

    data = cursor.fetchall()
    conn.close()

    if data:
        return {row["data_key"]: row["data_value"] for row in data}
    return None

def get_all_data(admin_token):
    """Allows an admin to retrieve all stored data"""
    payload = verify_jwt(admin_token)
    if not payload or not payload.get("is_admin"):
        print("❌ Access denied: Only admins can retrieve all data.")
        return None

    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT users.username, user_data.data_key, user_data.data_value 
        FROM user_data 
        JOIN users ON user_data.user_id = users.id
    """)

    data = cursor.fetchall()
    conn.close()

    if data:
        return {row["username"]: {row["data_key"]: row["data_value"]} for row in data}
    return None

def delete_user_data(username: str):
    """Deletes all data associated with a specific user from the user_data table."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Get the user_id of the specified user
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    if user:
        user_id = user[0]
        # Delete all data from the user_data table for the user
        cursor.execute("DELETE FROM user_data WHERE user_id = ?", (user_id,))
        conn.commit()
        print(f"✅ All data for user {username} has been successfully deleted.")
    else:
        print(f"⚠️ User {username} not found.")
    
    conn.close()


# Create the database
create_db()

# Add example users
add_user("admin", "SecurePass123", is_admin=True)
add_user("user1", "UserPass456", is_admin=False)
# add_user_data("user1", "This is a sample data entry.")
# delete_user_data("user1")
# Add user data
# add_user_data("user1", "user1@example.com")
# add_user_data("user1", "+123456789")

# Authenticate user and generate a token
if authenticate_user("admin", "SecurePass123"):
    admin_token = create_jwt("admin", True)
    print("🔑 Admin JWT Token:", admin_token)
    # Verify admin and fetch all data
    all_data = get_all_data(admin_token)
    if all_data:
        print("📂 All Data:", all_data)

# Fetch user data
user_data = get_user_data("user1")
if user_data:
    print("📂 User1 Data:", user_data)

