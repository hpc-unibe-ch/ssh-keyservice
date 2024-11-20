import sqlite3

# Define a named tuple for SSH keys
from collections import namedtuple
SSHKey = namedtuple('SSHKey', ['id', 'ssh_key', 'comment'])

def add_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    try:
        cursor.execute('''
        INSERT INTO users (username)
        VALUES (?)
        ''', (username,))
        conn.commit()
    except sqlite3.IntegrityError as e:
        print(f"Error: {e}")
    finally:
        conn.close()

def add_ssh_key(username, ssh_key, comment):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    try:
        # Get user ID
        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        if not user:
            print("User not found.")
            return

        user_id = user[0]

        # Insert SSH key
        cursor.execute('''
        INSERT INTO ssh_keys (user_id, ssh_key, comment)
        VALUES (?, ?, ?)
        ''', (user_id, ssh_key, comment))
        conn.commit()
    except sqlite3.IntegrityError as e:
        print(f"Error: {e}")
    finally:
        conn.close()

def user_exists(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Query the database for the username
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()  # Returns None if the user doesn't exist

    conn.close()
    return user is not None

def get_user_keys(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Query to get user keys
    cursor.execute('''
    SELECT k.id, k.ssh_key, k.comment
    FROM users u
    JOIN ssh_keys k ON u.id = k.user_id
    WHERE u.username = ?
    ''', (username,))
    rows = cursor.fetchall()

    conn.close()

    # Convert rows to a list of SSHKey named tuples
    return [SSHKey(*row) for row in rows]

def delete_user_ssh_key(username, key_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    try:
        # Ensure the key belongs to the user
        cursor.execute('''
        DELETE FROM ssh_keys
        WHERE id = ? AND user_id = (SELECT id FROM users WHERE username = ?)
        ''', (key_id, username))

        if cursor.rowcount == 0:
            print(f"No key found with ID {key_id} for user {username}.")
        else:
            print(f"Key with ID {key_id} deleted successfully for user {username}.")
        conn.commit()
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()
