# --- Part 1: Imports and Setup ---

import sqlite3
import bcrypt
import click
import secrets  # For CSRF tokens
from flask.cli import with_appcontext
from flask import Flask, render_template, request, redirect, url_for, session, g

# Create our Flask application
app = Flask(__name__)

# This is a secret key used to keep the user's "session" secure.
app.secret_key = 'my_super_secret_key_12345'

# Define the name of our database file
DATABASE = 'users.db'

# --- Part 2: Database Functions ---

# Function to get a connection to the database
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        # This line makes the database return data as dictionaries
        db.row_factory = sqlite3.Row
    return db

# Function to close the database connection when the app shuts down
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# This is the function that will create the database tables
def init_db():
    db = get_db()
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()

# This new function creates the 'init-db' command for the terminal
@click.command('init-db')
@with_appcontext
def init_db_command():
    """Clears the existing data and creates new tables."""
    init_db()
    click.echo('Initialized the database.') # This will print a success message

# This line officially adds our new command to the Flask app
app.cli.add_command(init_db_command)


# --- Part 3: Our Web Page Routes (Controllers) ---

# Route for the Home/Sign-up page
@app.route('/')
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # --- CSRF TOKEN CHECK ---
        if request.form.get('csrf_token') != session.get('csrf_token'):
            return render_template('signup.html', error="Invalid request. Please try again.")

        username = request.form['username']
        password = request.form['password']

        # --- SERVER-SIDE INPUT VALIDATION ---
        if len(password) < 8:
            return render_template('signup.html', error="Password must be at least 8 characters long.")
        if len(username) > 20:
            return render_template('signup.html', error="Username must be 20 characters or less.")
        
        # --- PASSWORD HASHING ---
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        db = get_db()
        try:
            db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            db.commit()
        except sqlite3.IntegrityError:
            return render_template('signup.html', error="Username already taken.")
        
        return redirect(url_for('login'))

    # --- CSRF TOKEN GENERATION (for GET request) ---
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    
    return render_template('signup.html')

# Route for the Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # --- CSRF TOKEN CHECK ---
        if request.form.get('csrf_token') != session.get('csrf_token'):
            return render_template('login.html', error="Invalid request. Please try again.")

        username = request.form['username']
        password = request.form['password'].encode('utf-8') 
        db = get_db()
        
        # --- FIX: SQL INJECTION (The RIGHT way) ---
        print("Executing SECURE query...")
        user_data = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        # --- SECURE PASSWORD CHECK ---
        if user_data and bcrypt.checkpw(password, user_data['password']):
            session['username'] = user_data['username']
            # Regenerate token on successful login
            session['csrf_token'] = secrets.token_hex(16) 
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid username or password.")

    # --- CSRF TOKEN GENERATION (for GET request) ---
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    
    return render_template('login.html')

# Route for the protected Dashboard
@app.route('/dashboard')
def dashboard():
    # --- SECURITY: Session Management ---
    if 'username' in session:
        # --- FIX: XSS ---
        # By NOT using '| safe', Flask auto-escapes the username.
        return render_template('dashboard.html', username=session['username'])
    
    return redirect(url_for('login'))

# Route for logging out
@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('csrf_token', None) # Clear CSRF token on logout
    return redirect(url_for('login'))


# --- Part 4: Run the Application ---

if __name__ == '__main__':
    app.run(debug=True)