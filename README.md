1. Introduction:
In today's digitally-driven world, web applications are the primary interface for business, finance, healthcare, and social interaction. From online banking and e-commerce to electronic health records and cloud services, users entrust these applications with vast amounts of sensitive personal and financial data. Consequently, these applications have become the single most significant attack vector for cybercriminals seeking to steal data, commit fraud, or disrupt services. A single security vulnerability can lead to catastrophic data breaches, resulting in severe financial losses, regulatory penalties, and an irreversible loss of customer trust.
Secure Web Application Development is the critical, foundational practice of building web services with security integrated at every stage of the lifecycle, rather than treating it as an afterthought. It represents a proactive shift from reacting to breaches to preventing them. This discipline requires developers and security professionals to operate with a "defense in depth" mindset, understanding that no single security measure is foolproof.
This project serves as a practical, hands-on exploration of this discipline. It moves beyond theoretical concepts by tasking a developer to build a core, high-risk component of any modern application: a user sign-up and login system. This system is then systematically analyzed for some of the most common and devastating vulnerabilities that plague the web today:
•	SQL Injection (SQLi): A critical vulnerability where an attacker can interfere with an application's database queries, allowing them to bypass authentication, view all user data, or even delete the entire database.
•	Cross-Site Scripting (XSS): An attack where malicious code is injected into a trusted website. This code then runs in a victim's browser, enabling the attacker to steal session cookies, capture login credentials, or perform actions on behalf of the user.
•	Cross-Site Request Forgery (CSRF): A subtle but powerful attack that tricks a logged-in user's browser into sending an unintended, malicious request to an application.
•	Insufficient Input Validation: A fundamental flaw where the application fails to properly sanitize or reject user-supplied data, opening the door for a wide range of attacks.
By first building a functional application, then executing these attacks in a controlled "sandbox" environment, and finally implementing the correct, modern security countermeasures, this project provides a foundational understanding of an attacker's mindset and a defender's essential toolkit. The skills demonstrated here such as parameterized queries, output escaping, tokenization, and server-side validation are not merely academic; they are the fundamental daily practices required to build safe, secure, and trustworthy web applications.

2. Project Objective:
The fundamental objective of this project was to build a practical, hands-on understanding of web application security. This was achieved by constructing a sign-up and login application, identifying its built-in security flaws, executing attacks to prove the vulnerabilities, and finally, implementing the correct security measures to fix them.
To achieve this overarching goal, the project was broken down into several key learning outcomes:
•	Build a full-stack web application using Python, the Flask framework, and an SQLite database.
•	Implement secure user authentication, including password hashing using bcrypt to ensure passwords are never stored in plain text.
•	Demonstrate and prevent SQL Injection by moving from an insecure, string-formatted query to a secure, parameterized query.
•	Demonstrate and prevent Cross-Site Scripting (XSS) by identifying the misuse of a "safe" filter and leveraging Flask's built-in auto-escaping.
•	Apply server-side input validation to enforce business rules (e.g., minimum password length) and reject bad data.
•	Implement Cross-Site Request Forgery (CSRF) protection by using a session-based token to validate all form submissions.
3. System Setup and Prerequisites:
This project was built using a standard Python development environment. The web application framework Flask was chosen for its simplicity and power, and bcrypt was used for modern password hashing.
The primary tools and libraries used were:
•	Python 3.10+ (and the pip package installer)
•	Visual Studio Code (as the primary code editor)
•	Flask: The web server and application framework.
•	bcrypt: The library used for hashing and checking passwords.
•	Google Chrome: The web browser used for testing and vulnerability demonstration.
The necessary libraries were installed using the pip command:
pip install Flask bcrypt

 


The project was structured with a main app.py file, a schema.sql for database setup, a static folder for CSS and images, and a templates folder for the HTML files.
                                         

4. Project Tasks and Execution:
4.1. Application and Database Setup:
The first task was to build the "brain" of the application. The app.py file contains all the Python code (routes) for handling user requests, such as showing the login page or processing a sign-up form.
A schema.sql file was created to define the users table, which includes columns for an id, a username, and a password.
The database (a file named users.db) was initialized using a custom Flask command in the terminal: flask --app app init-db
 

 
 
                  
	     	
 		

4.2. Vulnerability 1: SQL Injection (SQLi):
SQL Injection is an attack where a malicious user inserts their own SQL code into a data field (like a username box). If the application is vulnerable, it may run the attacker's code, allowing them to bypass security or steal the entire database.
The Attack
The application was first written with a vulnerable login query:
# VULNERABLE CODE
query = f"SELECT * FROM users WHERE username = '{username}'"
user_data = db.execute(query).fetchone()

if user_data: # Insecure check!
    session['username'] = user_data['username']
    return redirect(url_for('dashboard'))

This code is vulnerable in two ways:
1.	It uses an "f-string" to directly paste the user's input into the query.
2.	It only checks if user_data exists, not if the password is correct.
By entering ' OR '1'='1 as the username, the final query became: SELECT * FROM users WHERE username = '' OR '1'='1'
Since '1'='1' is always true, the database returned the first user in the table, and the application logged us in without a password.
                                               
 

The Fix
The vulnerability was fixed in two parts:
1.	The query was changed to a parameterized query. This sends the query template and the data to the database separately, so the user's input is never executed as code.
2.	The if statement was fixed to also check the password with bcrypt.

3.	# SECURE CODE
4.	user_data = db.execute(
5.	    "SELECT * FROM users WHERE username = ?", (username,)
6.	).fetchone()
7.	
8.	if user_data and bcrypt.checkpw(password, user_data['password']):
9.	    # Login is now secure

With the fix in place, the same attack was attempted. The database no longer found a match, and the bcrypt check failed, resulting in a correct "Invalid username or password" error.
                                      
                                        

 
4.3. Vulnerability 2: Cross-Site Scripting (XSS):
XSS is an attack where a malicious user injects client-side script (like JavaScript) into a website. When another user (like an admin) views the page, that script runs in their browser, allowing the attacker to steal session cookies, redirect the user, or deface the site.
The Attack
To test this, a new user was created with a malicious username: <script>alert('You have been hacked!');</script>
The dashboard was written with a vulnerable line of HTML (in dashboard.html):
<h1>Welcome, {{ username | safe }}!</h1>
The | safe filter explicitly told Flask, "I trust this data, do not escape it, run it as raw HTML." When the dashboard loaded, the browser executed the <script> tag and showed an alert box.

 
The Fix
The fix was simple: remove the | safe filter.
<h1>Welcome, {{ username }}!</h1>
 
By default, Flask's templating engine auto-escapes all data. It converts special characters into their harmless HTML equivalents. The malicious username was now rendered as simple text, completely neutralizing the attack.
 
4.4. Additional Security Measures (Defense in Depth):
Fixing SQLi and XSS is critical, but a secure application requires layers of defense. Two more measures were added.
1. Server-Side Input Validation
A rule was added to the /signup route to reject passwords that are too short. This prevents users from choosing weak, easily-guessed passwords.
if len(password) < 8:
    return render_template('signup.html', error="Password must be at least 8 characters long.") 
                                
2. Cross-Site Request Forgery (CSRF) Protection
A CSRF token was implemented to protect logged-in users.
1.	When a user visits a form, a unique, secret token is generated and stored in their session.
2.	This token is also placed in a hidden field in the HTML form.
3.	When the form is submitted, the server checks that the token from the form matches the token in the session.
An attacker's website cannot guess this token, so any forged requests are rejected.
# In app.py
if request.form.get('csrf_token') != session.get('csrf_token'):
    return render_template('login.html', error="Invalid request...")

# In login.html
<input type="hidden" name="csrf_token" value="{{ session.csrf_token }}">

