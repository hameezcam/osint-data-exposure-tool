import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets

def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    
    # Users table with blocking features
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            failed_login_attempts INTEGER DEFAULT 0,
            last_failed_login TIMESTAMP,
            account_locked_until TIMESTAMP
        )
    ''')
    
    # Sessions table
    c.execute('''
        CREATE TABLE IF NOT EXISTS user_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_token TEXT UNIQUE NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')
    
    # Security logs table
    c.execute('''
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            activity_type TEXT NOT NULL,
            description TEXT,
            ip_address TEXT,
            user_agent TEXT,
            status TEXT DEFAULT 'success',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # IP blocking table
    c.execute('''
        CREATE TABLE IF NOT EXISTS ip_blocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            failed_attempts INTEGER DEFAULT 0,
            last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            blocked_until TIMESTAMP,
            is_permanent BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create indexes
    c.execute('CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(session_token)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_security_logs_user_id ON security_logs(user_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_ip_blocks_ip ON ip_blocks(ip_address)')

    conn.commit()
    conn.close()

def is_ip_blocked(ip_address):
    """Check if an IP address is currently blocked"""
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    
    c.execute('''
        SELECT blocked_until, is_permanent 
        FROM ip_blocks 
        WHERE ip_address = ? AND (blocked_until > CURRENT_TIMESTAMP OR is_permanent = 1)
    ''', (ip_address,))
    
    result = c.fetchone()
    conn.close()
    
    return result is not None

def increment_failed_attempt(ip_address, username=None):
    """Increment failed attempt counter for IP and optionally for user"""
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    
    # Update IP failed attempts
    c.execute('''
        INSERT OR REPLACE INTO ip_blocks (ip_address, failed_attempts, last_attempt, blocked_until)
        VALUES (?, 
                COALESCE((SELECT failed_attempts FROM ip_blocks WHERE ip_address = ?), 0) + 1,
                CURRENT_TIMESTAMP,
                CASE 
                    WHEN COALESCE((SELECT failed_attempts FROM ip_blocks WHERE ip_address = ?), 0) + 1 >= 5 THEN 
                        datetime('now', '+15 minutes')
                    ELSE NULL
                END
               )
    ''', (ip_address, ip_address, ip_address))
    
    # Update user failed attempts if username provided
    if username:
        c.execute('''
            UPDATE users 
            SET failed_login_attempts = failed_login_attempts + 1,
                last_failed_login = CURRENT_TIMESTAMP,
                account_locked_until = CASE 
                    WHEN failed_login_attempts + 1 >= 3 THEN 
                        datetime('now', '+30 minutes')
                    ELSE NULL
                END
            WHERE username = ?
        ''', (username,))
    
    conn.commit()
    conn.close()

def reset_failed_attempts(username, ip_address=None):
    """Reset failed attempts for user and optionally for IP"""
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    
    # Reset user failed attempts
    c.execute('''
        UPDATE users 
        SET failed_login_attempts = 0,
            account_locked_until = NULL
        WHERE username = ?
    ''', (username,))
    
    # Reset IP failed attempts if provided
    if ip_address:
        c.execute('''
            DELETE FROM ip_blocks WHERE ip_address = ?
        ''', (ip_address,))
    
    conn.commit()
    conn.close()

def is_user_locked(username):
    """Check if user account is locked due to failed attempts"""
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    
    c.execute('''
        SELECT account_locked_until 
        FROM users 
        WHERE username = ? AND account_locked_until > CURRENT_TIMESTAMP
    ''', (username,))
    
    result = c.fetchone()
    conn.close()
    
    return result is not None

def register_user(username, email, password):
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()

        # Check if username or email already exists
        c.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
        existing_user = c.fetchone()
        
        if existing_user:
            conn.close()
            return False, "Username or email already exists"

        hashed_password = generate_password_hash(password)

        c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", 
                 (username, email, hashed_password))
        user_id = c.lastrowid
        
        # Log the registration
        c.execute("INSERT INTO security_logs (user_id, activity_type, description) VALUES (?, ?, ?)",
                 (user_id, 'registration', 'User account created'))
        
        conn.commit()
        conn.close()
        return True, "User registered successfully"
    except sqlite3.IntegrityError as e:
        if "username" in str(e):
            return False, "Username already exists"
        elif "email" in str(e):
            return False, "Email already exists"
        else:
            return False, "Registration failed"
    except Exception as e:
        return False, f"Registration error: {str(e)}"
    finally:
        if 'conn' in locals():
            conn.close()

def validate_user(username, password, ip_address=None, user_agent=None):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()

    # Check if IP is blocked
    if ip_address and is_ip_blocked(ip_address):
        conn.close()
        return False, "IP address temporarily blocked due to too many failed attempts. Please try again later."

    # Check if user account is locked
    if is_user_locked(username):
        c.execute('''
            SELECT account_locked_until FROM users WHERE username = ?
        ''', (username,))
        result = c.fetchone()
        conn.close()
        if result:
            locked_until = result[0]
            return False, f"Account temporarily locked. Please try again after {locked_until}"

    c.execute("SELECT id, password FROM users WHERE username=?", (username,))
    result = c.fetchone()
    
    if result:
        user_id, stored_password = result
        
        if check_password_hash(stored_password, password):
            # Reset failed attempts on successful login
            reset_failed_attempts(username, ip_address)
            
            # Update last login time
            c.execute("UPDATE users SET last_login=CURRENT_TIMESTAMP WHERE id=?", (user_id,))
            
            # Log successful login
            c.execute("INSERT INTO security_logs (user_id, activity_type, description, ip_address, user_agent, status) VALUES (?, ?, ?, ?, ?, ?)",
                     (user_id, 'login', 'Successful login', ip_address, user_agent, 'success'))
            
            conn.commit()
            conn.close()
            return True, user_id
        else:
            # Increment failed attempts
            increment_failed_attempt(ip_address, username)
            
            # Log failed login attempt
            c.execute("INSERT INTO security_logs (user_id, activity_type, description, ip_address, user_agent, status) VALUES (?, ?, ?, ?, ?, ?)",
                     (user_id, 'login', 'Failed login attempt', ip_address, user_agent, 'failure'))
            
            conn.commit()
            conn.close()
            
            # Check if user is now locked after this attempt
            if is_user_locked(username):
                return False, "Account temporarily locked due to too many failed attempts. Please try again in 30 minutes."
            else:
                return False, "Invalid credentials"
    
    conn.close()
    return False, "User not found"

def create_session(user_id, ip_address=None, user_agent=None):
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        
        # Generate secure session token
        session_token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(days=7)
        
        c.execute('''
            INSERT INTO user_sessions (user_id, session_token, ip_address, user_agent, expires_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, session_token, ip_address, user_agent, expires_at.isoformat()))
        
        conn.commit()
        conn.close()
        return session_token
    except Exception as e:
        print(f"Error creating session: {e}")
        return None

def validate_session(session_token):
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        
        c.execute('''
            SELECT user_id, last_activity, expires_at 
            FROM user_sessions 
            WHERE session_token=? AND is_active=1 AND expires_at > CURRENT_TIMESTAMP
        ''', (session_token,))
        
        result = c.fetchone()
        if result:
            user_id, last_activity, expires_at = result
            
            # Update last activity
            c.execute('''
                UPDATE user_sessions 
                SET last_activity=CURRENT_TIMESTAMP 
                WHERE session_token=?
            ''', (session_token,))
            
            conn.commit()
            conn.close()
            return user_id
        else:
            conn.close()
            return None
    except Exception as e:
        print(f"Error validating session: {e}")
        return None

def revoke_session(session_token):
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        
        c.execute("UPDATE user_sessions SET is_active=0 WHERE session_token=?", (session_token,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error revoking session: {e}")
        return False

def get_user_by_id(user_id):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    
    c.execute('''
        SELECT id, username, email, created_at, last_login
        FROM users 
        WHERE id=? AND is_active=1
    ''', (user_id,))
    
    result = c.fetchone()
    conn.close()
    
    if result:
        return {
            'id': result[0],
            'username': result[1],
            'email': result[2],
            'created_at': result[3],
            'last_login': result[4]
        }
    return None
