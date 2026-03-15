// server.js
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// PostgreSQL connection
const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'workershiredb',
  password: 'Harshit@postgre',
  port: 5432,
});

// Helper function to validate email format
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// User Registration
app.post('/api/register', async (req, res) => {
  try {
    const { 
      firstName, 
      lastName, 
      email, 
      contactNumber, 
      password, 
      confirmPassword, 
      userType,
      profession,
      skills
    } = req.body;

    // Basic validation
    if (!firstName || !lastName || !email || !contactNumber || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }

    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long' });
    }

    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    // Hash password
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Begin transaction
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Insert into users table
      const userResult = await client.query(
        `INSERT INTO users (first_name, last_name, email, contact_number, password_hash, user_type) 
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
        [firstName, lastName, email, contactNumber, passwordHash, userType]
      );

      const userId = userResult.rows[0].id;

      // If worker, insert additional info into worker_profiles
      if (userType === 'worker') {
        if (!profession || !skills) {
          throw new Error('Profession and skills are required for workers');
        }

        await client.query(
          `INSERT INTO worker_profiles (user_id, profession, skills) 
           VALUES ($1, $2, $3)`,
          [userId, profession, skills]
        );
      }

      await client.query('COMMIT');

      // Generate JWT token
      const token = jwt.sign(
        { id: userId, email, userType },
        'your_jwt_secret', // Replace with a secure secret key
        { expiresIn: '24h' }
      );

      res.status(201).json({
        message: 'Registration successful',
        token,
        user: {
          id: userId,
          firstName,
          lastName,
          email,
          userType
        }
      });
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// User Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password, userType } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Get user from database
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1 AND user_type = $2',
      [email, userType]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];

    // Compare password
    const isPasswordValid = await bcrypt.compare(password, user.password_hash);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Log login attempt
    await pool.query(
      'INSERT INTO login_logs (user_id, ip_address, user_agent) VALUES ($1, $2, $3)',
      [user.id, req.ip, req.headers['user-agent']]
    );

    // Generate JWT token
    const token = jwt.sign(
      { 
        id: user.id, 
        email: user.email, 
        userType: user.user_type 
      },
      'your_jwt_secret', // Replace with a secure secret key
      { expiresIn: '24h' }
    );

    res.status(200).json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        firstName: user.first_name,
        lastName: user.last_name,
        email: user.email,
        userType: user.user_type
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access denied' });
  }

  jwt.verify(token, 'your_jwt_secret', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Protected route example
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    
    const userResult = await pool.query(
      'SELECT id, first_name, last_name, email, contact_number, user_type FROM users WHERE id = $1',
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userResult.rows[0];
    
    // If worker, get additional profile information
    if (user.user_type === 'worker') {
      const workerResult = await pool.query(
        'SELECT profession, skills, availability_status, rating FROM worker_profiles WHERE user_id = $1',
        [userId]
      );
      
      if (workerResult.rows.length > 0) {
        user.workerProfile = workerResult.rows[0];
      }
    }

    res.status(200).json({ user });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});