import os
import sqlite3
from flask import Flask, request, jsonify
import logging

app = Flask(__name__)

# VIOLATION 1: Hardcoded Credentials (CC7 - System Ops)
# Never store secrets in plain text.
AWS_ACCESS_KEY = "AKIA5555555555555555"
DB_PASSWORD = "super_secret_password_123"

# VIOLATION 2: Insecure Logging (CC7 - System Ops)
# Logging sensitive data (PII/Passwords) creates a data leak.
logging.basicConfig(filename='app.log', level=logging.DEBUG)

def get_db_connection():
    conn = sqlite3.connect('users.db')
    return conn

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    # VIOLATION 3: Logging Sensitive Data (CC7 - System Ops)
    # The logs now contain user passwords. If logs are leaked, accounts are compromised.
    logging.info(f"User attempting login: {username} with password: {password}")

    conn = get_db_connection()
    cursor = conn.cursor()

    # VIOLATION 4: SQL Injection (CC8 - Change Management / Quality)
    # Using f-strings to build queries allows attackers to execute arbitrary SQL.
    # An attacker can input: " ' OR '1'='1 " to bypass authentication.
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    
    # VIOLATION 5: No Error Handling / Information Leakage (CC7 - System Ops)
    # If this query fails, the raw stack trace might be exposed to the user/logs.
    cursor.execute(query)
    user = cursor.fetchone()

    conn.close()

    if user:
        # VIOLATION 6: Returning Sensitive Data (CC7 - System Ops)
        # We are returning the entire user row, which might include their password hash, SSN, etc.
        return jsonify({"status": "success", "user_data": user}), 200
    else:
        return jsonify({"status": "failure"}), 401

@app.route('/admin/data', methods=['GET'])
def get_admin_data():
    # VIOLATION 7: Broken Access Control (CC7 - System Ops)
    # There is no check here to see if the requester is actually an admin.
    # Anyone who guesses this URL can access the data.
    return jsonify({"secret_data": "Company Financials"}), 200

if __name__ == '__main__':
    # VIOLATION 8: Running in Debug Mode in "Production" context
    # Debug mode exposes the interactive debugger and stack traces to the public.
    app.run(debug=True, port=5000)
