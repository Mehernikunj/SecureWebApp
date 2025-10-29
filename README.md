Secure Web Application Development
Introduction:
   
In today's digitally-driven world, web applications are the primary interface for business, finance, healthcare, and social interaction. From online banking and e-commerce to electronic health records and cloud services, users entrust these applications with vast amounts of sensitive personal and financial data. Consequently, these applications have become the single most significant attack vector for cybercriminals seeking to steal data, commit fraud, or disrupt services. A single security vulnerability can lead to catastrophic data breaches, resulting in severe financial losses, regulatory penalties, and an irreversible loss of customer trust.

Secure Web Application Development is the critical, foundational practice of building web services with security integrated at every stage of the lifecycle, rather than treating it as an afterthought. It represents a proactive shift from reacting to breaches to preventing them. This discipline requires developers and security professionals to operate with a "defense in depth" mindset, understanding that no single security measure is foolproof.

This project serves as a practical, hands-on exploration of this discipline. It moves beyond theoretical concepts by tasking a developer to build a core, high-risk component of any modern application: a user sign-up and login system. This system is then systematically analyzed for some of the most common and devastating vulnerabilities that plague the web today:

•	SQL Injection (SQLi): A critical vulnerability where an attacker can interfere with an application's database queries, allowing them to bypass authentication, view all user data, or even delete the entire database.

•	Cross-Site Scripting (XSS): An attack where malicious code is injected into a trusted website. This code then runs in a victim's browser, enabling the attacker to steal session cookies, capture login credentials, or perform actions on behalf of the user.

•	Cross-Site Request Forgery (CSRF): A subtle but powerful attack that tricks a logged-in user's browser into sending an unintended, malicious request to an application.

•	Insufficient Input Validation: A fundamental flaw where the application fails to properly sanitize or reject user-supplied data, opening the door for a wide range of attacks.

By first building a functional application, then executing these attacks in a controlled "sandbox" environment, and finally implementing the correct, modern security countermeasures, this project provides a foundational understanding of an attacker's mindset and a defender's essential toolkit. The skills demonstrated here such as parameterized queries, output escaping, tokenization, and server-side validation are not merely academic; they are the fundamental daily practices required to build safe, secure, and trustworthy web applications.

Project Objective:
The fundamental objective of this project was to build a practical, hands-on understanding of web application security. This was achieved by constructing a sign-up and login application, identifying its built-in security flaws, executing attacks to prove the vulnerabilities, and finally, implementing the correct security measures to fix them.

To achieve this overarching goal, the project was broken down into several key learning outcomes:

•	Build a full-stack web application using Python, the Flask framework, and an SQLite database.

•	Implement secure user authentication, including password hashing using bcrypt to ensure passwords are never stored in plain text.

•	Demonstrate and prevent SQL Injection by moving from an insecure, string-formatted query to a secure, parameterized query.

•	Demonstrate and prevent Cross-Site Scripting (XSS) by identifying the misuse of a "safe" filter and leveraging Flask's built-in auto-escaping.

•	Apply server-side input validation to enforce business rules (e.g., minimum password length) and reject bad data.

•	Implement Cross-Site Request Forgery (CSRF) protection by using a session-based token to validate all form submissions.

