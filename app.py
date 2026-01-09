from flask import Flask, request, render_template, flash, session, redirect
import sqlite3 
import hashlib 
from functools import wraps
from datetime import datetime

app = Flask(__name__)
app.secret_key = "crm_secret_key_2025"

# Check user role
def roles_permitted(roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if 'uid' in session and session['role'] in roles:
                return f(*args, **kwargs)
            else:
                flash('ERROR: you need permission to access this page')
                return redirect('/login')
        return wrapper
    return decorator

# Open database
def get_db_conn():
    db = sqlite3.connect('crm.db')
    db.row_factory = sqlite3.Row
    return db 

# Create tables
def initialize_db():
    db = get_db_conn()
    cursor = db.cursor() 
    cursor.execute("PRAGMA foreign_keys=ON")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            uid INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE, 
            password TEXT NOT NULL,
            first_name TEXT,
            last_name TEXT,
            email TEXT,
            role TEXT DEFAULT 'employee',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active TEXT DEFAULT 'active'
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS customers (
            cid INTEGER PRIMARY KEY AUTOINCREMENT,
            created_by_user_id INTEGER,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT NOT NULL,
            status TEXT DEFAULT 'Leads',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP,
            last_contact_date TIMESTAMP,
            FOREIGN KEY (created_by_user_id) REFERENCES users(uid)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS interactions (
            interaction_id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER,
            user_id INTEGER,
            interaction_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            notes TEXT,
            customer_responded TEXT DEFAULT 'yes',
            FOREIGN KEY (customer_id) REFERENCES customers(cid),
            FOREIGN KEY (user_id) REFERENCES users(uid)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            comment_id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER,
            user_id INTEGER,
            comment_text TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (customer_id) REFERENCES customers(cid),
            FOREIGN KEY (user_id) REFERENCES users(uid)
        )
    """)
    
    db.commit()
    db.close()

# Encrypt password
def hash_password(username, password):
    pw = username + password
    hashed = hashlib.sha512(pw.encode('utf-8')).hexdigest()
    return hashed

# Redirect to dashboard
@app.route('/')
def home():
    if 'uid' in session:
        if session['role'] == 'employee':
            return redirect('/employee')
        elif session['role'] == 'manager':
            return redirect('/manager')
        elif session['role'] == 'admin':
            return redirect('/admin')
    return redirect('/login')

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db_conn()
        cursor = db.cursor()
        user = cursor.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        db.close()
        
        if user:
            hashed_password = hash_password(username, password)
            if user['password'] == hashed_password:
                session['uid'] = user['uid']
                session['username'] = user['username']
                session['role'] = user['role']
                session['first_name'] = user['first_name']
                session['last_name'] = user['last_name']
                
                if user['role'] == 'employee':
                    return redirect('/employee')
                elif user['role'] == 'manager':
                    return redirect('/manager')
                elif user['role'] == 'admin':
                    return redirect('/admin')
            else:
                flash('ERROR: Wrong password')
                return render_template('login_form.html', username=username)
        else:
            flash('ERROR: Username not found')
            return render_template('login_form.html', username=username)
    
    return render_template('login_form.html')

# Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

# Employee dashboard
@app.route('/employee')
@roles_permitted(['employee'])
def employee():
    db = get_db_conn()
    cursor = db.cursor()
    
    uid = session['uid']
    
    customers_added = cursor.execute(
        "SELECT COUNT(*) as count FROM customers WHERE created_by_user_id = ?", 
        (uid,)
    ).fetchone()['count']
    
    contacts_month = cursor.execute(
        "SELECT COUNT(*) as count FROM interactions WHERE user_id = ? AND interaction_date >= date('now', '-30 days')", 
        (uid,)
    ).fetchone()['count']
    
    contacts_week = cursor.execute(
        "SELECT COUNT(*) as count FROM interactions WHERE user_id = ? AND interaction_date >= date('now', '-7 days')", 
        (uid,)
    ).fetchone()['count']
    
    contacts_day = cursor.execute(
        "SELECT COUNT(*) as count FROM interactions WHERE user_id = ? AND interaction_date >= date('now')", 
        (uid,)
    ).fetchone()['count']
    
    db.close()
    
    return render_template('employee_dashboard.html', 
                         customers_added=customers_added,
                         contacts_month=contacts_month,
                         contacts_week=contacts_week,
                         contacts_day=contacts_day)

# Manager dashboard
@app.route('/manager')
@roles_permitted(['manager'])
def manager():
    db = get_db_conn()
    cursor = db.cursor()
    
    employees = cursor.execute(
        "SELECT u.uid, u.username, COUNT(i.interaction_id) as contact_count FROM users u LEFT JOIN interactions i ON u.uid = i.user_id WHERE u.role = 'employee' GROUP BY u.uid ORDER BY contact_count DESC"
    ).fetchall()
    
    not_contacted = cursor.execute(
        "SELECT cid, first_name, last_name, last_contact_date FROM customers WHERE last_contact_date < date('now', '-7 days') OR last_contact_date IS NULL"
    ).fetchall()
    
    not_responding = cursor.execute(
        "SELECT c.cid, c.first_name, c.last_name, COUNT(i.interaction_id) as interaction_count FROM customers c LEFT JOIN interactions i ON c.cid = i.customer_id WHERE i.customer_responded = 'no' GROUP BY c.cid HAVING interaction_count >= 3"
    ).fetchall()
    
    categories = cursor.execute(
        "SELECT status, COUNT(*) as count FROM customers GROUP BY status"
    ).fetchall()
    
    db.close()
    
    return render_template('manager_dashboard.html',
                         employees=employees,
                         not_contacted=not_contacted,
                         not_responding=not_responding,
                         categories=categories)

# Admin dashboard
@app.route('/admin')
@roles_permitted(['admin'])
def admin():
    db = get_db_conn()
    cursor = db.cursor()
    
    users = cursor.execute("SELECT uid, username, first_name, last_name, role, is_active FROM users").fetchall()
    
    db.close()
    
    return render_template('admin_dashboard.html', users=users)

# Customer list
@app.route('/customers')
@roles_permitted(['employee'])  
def customers():
    db = get_db_conn()
    cursor = db.cursor()
    all_customers = cursor.execute("SELECT * FROM customers WHERE created_by_user_id=?", (session['uid'],)).fetchall()
    db.close()
    return render_template('customers.html', customers=all_customers)

# Add customer
@app.route('/add/customer', methods=['GET', 'POST'])
@roles_permitted(['employee'])
def add_customer():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name'] 
        email = request.form['email']
        
        db = get_db_conn()
        cursor = db.cursor()
        cursor.execute("INSERT INTO customers (first_name, last_name, email, created_by_user_id) VALUES (?, ?, ?, ?)",
                        (first_name, last_name, email, session['uid']))
        db.commit()
        db.close()
        
        flash('Customer added successfully!')
        return redirect('/customers')
    else:
        return render_template('add_customer.html')

# Edit customer
@app.route('/edit/customer/<int:cid>', methods=['GET', 'POST'])
@roles_permitted(['employee'])
def edit_customer(cid):
    db = get_db_conn()
    cursor = db.cursor()
    
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        status = request.form['status']
        comment_text = request.form.get('comment', '')
        
        cursor.execute("UPDATE customers SET first_name=?, last_name=?, email=?, status=?, updated_at=CURRENT_TIMESTAMP WHERE cid=?",
                       (first_name, last_name, email, status, cid))
        
        if comment_text:
            cursor.execute("INSERT INTO comments (customer_id, user_id, comment_text) VALUES (?, ?, ?)",
                           (cid, session['uid'], comment_text))
        
        db.commit()
        db.close()
        
        flash('Customer updated successfully!')
        return redirect('/customers')
    else:
        customer = cursor.execute("SELECT * FROM customers WHERE cid=?", (cid,)).fetchone()
        db.close()
        return render_template('edit_customer.html', customer=customer)

# Communication
@app.route('/communication/<int:cid>', methods=['GET', 'POST'])
@roles_permitted(['employee'])
def communication(cid):
    db = get_db_conn()
    cursor = db.cursor()
    
    if request.method == 'POST':
        comment_text = request.form['comment']
        local_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        cursor.execute("INSERT INTO comments (customer_id, user_id, comment_text, created_at) VALUES (?, ?, ?, ?)",
                       (cid, session['uid'], comment_text, local_time))
        
        cursor.execute("UPDATE customers SET last_contact_date=? WHERE cid=?", (local_time, cid))
        
        db.commit()
    
    comments = cursor.execute("SELECT c.*, u.first_name, u.last_name FROM comments c JOIN users u ON c.user_id = u.uid WHERE c.customer_id=? ORDER BY c.created_at DESC", (cid,)).fetchall()
    customer = cursor.execute("SELECT * FROM customers WHERE cid=?", (cid,)).fetchone()
    
    db.close()
    
    return render_template('communication.html', comments=comments, customer=customer)

# Add user
@app.route('/add/user', methods=['GET', 'POST'])
@roles_permitted(['admin'])
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password2 = request.form['password2']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        role = request.form['role']
        
        if password != password2:
            flash('ERROR: Passwords do not match')
            return render_template('add_user.html')
        
        db = get_db_conn()
        cursor = db.cursor()
        
        user = cursor.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user:
            flash('ERROR: Username already exists')
            return render_template('add_user.html')
        
        hashed_password = hash_password(username, password)
        cursor.execute("INSERT INTO users (username, password, first_name, last_name, email, role) VALUES (?, ?, ?, ?, ?, ?)",
                       (username, hashed_password, first_name, last_name, email, role))
        db.commit()
        db.close()
        
        flash('User created successfully!')
        return redirect('/admin')
    else:
        return render_template('add_user.html')

# Edit user
@app.route('/edit/user/<int:uid>', methods=['GET', 'POST'])
@roles_permitted(['admin'])
def edit_user(uid):
    db = get_db_conn()
    cursor = db.cursor()
    
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        role = request.form['role']
        
        cursor.execute("UPDATE users SET first_name=?, last_name=?, email=?, role=? WHERE uid=?",
                       (first_name, last_name, email, role, uid))
        db.commit()
        db.close()
        
        flash('User updated successfully!')
        return redirect('/admin')
    else:
        user = cursor.execute("SELECT * FROM users WHERE uid=?", (uid,)).fetchone()
        db.close()
        return render_template('edit_user.html', user=user)


if __name__ == '__main__':
    initialize_db()
    app.run(debug=True)