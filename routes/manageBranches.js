// routes/manageBranches.js

const express = require('express');
const ManageBranch = require('../models/manageBranch'); // Import the ManageBranch model
const bcrypt = require('bcrypt');
const router = express.Router();


// GET all branches
router.get('/branch', async (req, res) => {
    try {
      const branches = await ManageBranch.find(); // Fetch all branches from the database
      res.status(200).json(branches); // Send the retrieved branches as a response
    } catch (error) {
      res.status(500).json({ error: 'Error fetching branches', details: error.message });
    }
  });

// Create a new branch
router.post('/branch', async (req, res) => {
  const {
    category,
    name,
    contactNumber,
    email,
    username,
    password,
    confirmPassword,
    location,
    uploads,
    otherDetails,
    description,
    explanatoryMessage,
    restaurantTags,
    restaurantFeatures,
    restaurantTiming,
  } = req.body;

  try {
    const newBranch = new ManageBranch({
      category,
      name,
      contactNumber,
      email,
      username,
      password: await bcrypt.hash(password, 10), // Hash the password
      confirmPassword: await bcrypt.hash(confirmPassword, 10),
      location,
      uploads,
      otherDetails,
      description,
      explanatoryMessage,
      restaurantTags,
      restaurantFeatures,
      restaurantTiming,
    });

    await newBranch.save();
    res.status(201).json(newBranch);
  } catch (error) {
    res.status(500).json({ error: 'Error saving branch', details: error.message });
  }
});

// Update a branch by ID
router.put('/branch/:id', async (req, res) => {
  const branchId = req.params.id;
  const updatedData = req.body;

  try {
    const updatedBranch = await ManageBranch.findByIdAndUpdate(branchId, updatedData, { new: true });

    if (!updatedBranch) {
      return res.status(404).json({ message: 'Branch not found' });
    }

    res.status(200).json(updatedBranch);
  } catch (error) {
    res.status(500).json({ error: 'Error updating branch', details: error.message });
  }
});

// Delete a branch by ID
router.delete('/branch/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const deletedBranch = await ManageBranch.findByIdAndDelete(id);

    if (!deletedBranch) {
      return res.status(404).json({ message: 'Branch not found' });
    }

    res.status(200).json({ message: 'Branch deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting branch', details: error.message });
  }
});

// Export the router
module.exports = router;
