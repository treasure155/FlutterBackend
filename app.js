const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const cors = require('cors');
const bodyParser = require('body-parser');
require('dotenv').config();
const path = require('path');


const app = express();
app.use(cors());
app.use(bodyParser.json());

// MongoDB connection
mongoose.connect(process.env.MONGO_URI);

// User schema
const UserSchema = new mongoose.Schema({
  name: String,
  phone: String,
  email: { type: String, unique: true },
  password: String,
  profilePicture: String
});

const User = mongoose.model('User', UserSchema);


// Serve static files (e.g., profile pictures)
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));


// JWT Middleware to Authenticate Users
const authenticate = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1]; // Bearer token
  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(400).json({ message: 'Invalid token.' });
  }
};

// Nodemailer transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Registration API
app.post('/register', async (req, res) => {
  const { name, phone, email, password, profilePicture } = req.body;

  try {
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Set default profile picture if not provided
    const userPicture = profilePicture || 'default.png';  // Use a default image if none is provided

    // Create new user
    const newUser = new User({
      name,
      phone,
      email,
      password: hashedPassword,
      profilePicture: userPicture
    });

    // Save user to database
    await newUser.save();

    // Send verification email
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Verify your email',
      text: `Hi ${name}, please verify your email by clicking this link.`
    };

    transporter.sendMail(mailOptions);

    res.status(201).json({ message: 'User registered and verification email sent' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});


// Profile Route - Protected by JWT
app.get('/profile', authenticate, async (req, res) => {
  try {
    // Find user by ID from decoded JWT token
    const user = await User.findById(req.user.id).select('-password'); // Exclude password
    if (!user) return res.status(404).json({ message: 'User not found' });

    res.json({ user });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Start the server
const PORT = process.env.PORT || 31000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
