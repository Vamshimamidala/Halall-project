const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const User = require('../models/User');
const router = express.Router();

const JWT_SECRET = '024bd2518f5a241a27a38b6ad4b81f8b6281c62b6acd5387f64c482b53c9f28a';


// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, './uploads');
  
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  },
});
const upload = multer({ storage });
router.post('/upload', upload.single('image'), (req, res) => {
  try {
    // If file is successfully uploaded, multer stores info in req.file
    console.log(req.file); // Log file details
    res.status(200).json({ message: 'File uploaded successfully', filename: req.file.filename });
  } catch (error) {
    res.status(500).json({ message: 'File upload failed', error });
}
})

// Registration route
router.post('/register', upload.single('file'), async (req, res) => {
    const { businessName, email, contactNumber, address, city, postalCode, password } = req.body;
  
    try {
      // Log incoming request body
      console.log("Incoming registration data:", req.body);
  
      // Check if user already exists
      let user = await User.findOne({ email });
      if (user) {
        return res.status(400).json({ msg: 'User already exists' });
      }
  
      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);
  
      // Create new user
      user = new User({
        businessName,
        email,
        contactNumber,
        address,
        city,
        postalCode,
        password: hashedPassword,
        file: req.file ? req.file.path : null, // Safely handle file upload
      });
  
      // Save user to database
      await user.save();
  
      // Generate JWT token
      const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1h' });
  
      // Send response
      res.status(201).json({ token, msg: 'Registration successful' });
    } catch (err) {
      console.error("Error during registration:", err);
      res.status(500).json({ msg: 'Server error', error: err.message });
    }
  });
  

// Login route
router.post('/login', async (req, res) => {
    const { email, password } = req.body; 

    try {
        let user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ msg: 'Invalid credentials' });
        }

        console.log('User found:', user); // Log user details
        const isMatch = await bcrypt.compare(password, user.password);
        console.log('Password match:', isMatch); // Log password match status

        if (!isMatch) {
            return res.status(400).json({ msg: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, msg: 'Login successful' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});


// Middleware to verify the JWT and allow authenticated users only
const authMiddleware = (req, res, next) => {
    const authHeader = req.header('Authorization');
    console.log("Authorization Header:", authHeader); // Log the header for debugging

    if (!authHeader || !authHeader.startsWith('Bearer')) {
        return res.status(401).json({ msg: 'No token, authorization denied' });
    }

    const token = authHeader.replace('Bearer ', '');
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        console.error("Token verification error:", err); // Log any errors during token verification
        res.status(401).json({ msg: 'Token is not valid' });
    }
};


  
 
  
  // Change password route
  router.post('/change-password', authMiddleware, async (req, res) => {
    const { currentPassword, newPassword, confirmPassword } = req.body;
  
    try {
      // Fetch the user from the database by ID
      const user = await User.findById(req.user.id);
      if (!user) {
        return res.status(404).json({ msg: 'User not found' });
      }
  
      // Check if the current password matches the stored hashed password
      const isMatch = await bcrypt.compare(currentPassword, user.password);
      if (!isMatch) {
        return res.status(400).json({ msg: 'Current password is incorrect' });
      }
  
      // Check if new password and confirm password match
      if (newPassword !== confirmPassword) {
        return res.status(400).json({ msg: 'New password and confirm password do not match' });
      }
  
      // Hash the new password
      const hashedNewPassword = await bcrypt.hash(newPassword, 10);
  
      // Update the user's password in the database
      user.password = hashedNewPassword;
      await user.save();
  
      res.status(200).json({ msg: 'Password changed successfully' });
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error');
    }
  });

module.exports = router;
