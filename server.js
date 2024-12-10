import express from 'express';
import 'dotenv/config';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cors from 'cors';

// Importing the User schema
import User from './Schema/User.js';
import { nanoid } from 'nanoid';

const server = express();
const PORT = 3000;

// Regular expressions for validation
const emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/;

// Middleware
server.use(express.json());
server.use(cors());

// Database connection

mongoose.connect(process.env.DB_LOCATION, { 
  autoIndex: true
})
 

// Helper function to format response data
const formatDatatoSend = (user) => {
  const access_token = jwt.sign({ id: user._id }, process.env.SECRET_ACCESS_KEY);
  return {
    access_token,
    profile_img: user.personal_info.profile_img,
    username: user.personal_info.username,
    fullname: user.personal_info.fullname,
  };
};

// Helper function to generate a unique username
const generateUserName = async (email) => {
  let username = email.split('@')[0];
  const uniqueUsername = await User.exists({ 'personal_info.username': username });
  if (uniqueUsername) {
    username += nanoid().substring(0, 5);
  }
  return username;
};

// Signup endpoint
server.post('/signup', async (req, res) => {
  try {
    const { fullname, email, password } = req.body;

    // Input validation
    if (fullname.length < 3) {
      return res.status(403).json({ error: 'Full name must be greater than 3 characters.' });
    }
    if (!email.length || !emailRegex.test(email)) {
      return res.status(403).json({ error: 'Invalid email. Please check your input.' });
    }
    if (!passwordRegex.test(password)) {
      return res.status(403).json({
        error: 'Password must be 6-20 characters and include numeric, uppercase, and lowercase letters.',
      });
    }

    // Password hashing
    const hashed_password = await bcrypt.hash(password, 6);

    // Generating username
    const username = await generateUserName(email);

    // Creating a new user
    const user = new User({
      personal_info: { fullname, email, password: hashed_password, username },
    });

    // Saving the user to the database
    const savedUser = await user.save();
    return res.status(200).json(formatDatatoSend(savedUser));
  } catch (err) {
    if (err.code === 11000) {
      return res.status(500).json({ error: 'Email already exists.' });
    }
    console.error('Signup error:', err.message);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Signin endpoint
server.post('/signin', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Finding the user
    const user = await User.findOne({ 'personal_info.email': email });
    if (!user) {
      return res.status(403).json({ error: 'Email not found.' });
    }

    // Comparing passwords
    const isMatch = await bcrypt.compare(password, user.personal_info.password);
    if (!isMatch) {
      return res.status(403).json({ error: 'Incorrect password.' });
    }

    // Sending formatted response
    return res.status(200).json(formatDatatoSend(user));
  } catch (err) {
    console.error('Signin error:', err.message);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Catch-all error handler
server.use((err, req, res, next) => {
  console.error('Unhandled error:', err.stack);
  res.status(500).json({ error: 'Something went wrong.' });
});

// Starting the server
server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
