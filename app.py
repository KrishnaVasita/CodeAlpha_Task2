from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import os

app = Flask(__name__)
#  Vulnerable: Hardcoded secret key (exposes app to attacks)
#app.secret_key = 'supersecretkey'  # Security flaw: hardcoded secret

#Secure: Use environment variable for secret key
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'default_key')  # Secure secret

def get_db_connection():
    conn = sqlite3.connect('users.db')
    return conn

@app.route('/')
def index():
    if 'username' in session:
        return render_template('welcome.html', username=session['username'])  # ✅ Show welcome template
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        cursor = conn.cursor()
        # Vulnerable to SQL Injection!
        #cursor.execute(f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'")
        
        # Secure: Use parameterized queries to prevent SQL injection
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        
        user = cursor.fetchone()
        conn.close()
        if user:
            session['username'] = username
            return redirect(url_for('index'))  # Redirects to "/"
        return "Invalid credentials!"
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    # Insecure: Hardcoded debug mode
    #app.run(debug=False)
    
    # Secure: Use environment variable to control debug mode
    debug_mode = os.environ.get('FLASK_DEBUG', 'False') == 'True'
    app.run(debug=debug_mode)
