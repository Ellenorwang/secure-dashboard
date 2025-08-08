# Secure Dashboard

This project is a simple and secure authentication dashboard built with Node.js, Express, and MongoDB.  
It focuses on safe user registration, login, input validation, and basic encryption.

---

## Getting Started

## 1. Clone the repository

git clone https://github.com/your-username/secure-dashboard.git
cd secure-dashboard


## 2. Install dependencies
npm install

## 3. Set up environment variables
Create a .env file in the project root and add:
MONGO_URI=your_mongodb_connection_string
SESSION_SECRET=your_secret_key
PORT=3000

## 4. Run the application
npm start
The application will be available at http://localhost:3000

### Security Practices
Input Validation: Used express-validator to check and sanitize name, email, and bio inputs.

Output Encoding: Escaped user-provided values before displaying to prevent XSS.

Encryption: Passwords are hashed with bcrypt. Sensitive text fields are encrypted before storing in the database.

Dependency Management: Used npm audit and npm outdated to check for vulnerabilities and updates 
. env and node_modules are excluded from version control.

Lessons Learned
Fixed session handling issues by properly destroying sessions on logout.

Solved hashing problems by ensuring correct salt rounds for bcrypt.

Learned the importance of running npm audit early to avoid using vulnerable package
