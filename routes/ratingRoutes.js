// routes/ratingRoutes.js
const express = require('express');
const Rating = require('../models/Rating'); // Import the Rating model

const router = express.Router();



// GET all branches
router.get('/addRating', async (req, res) => {
    try {
      const rating = await Rating.find(); // Fetch all branches from the database
      res.status(200).json(rating); // Send the retrieved branches as a response
    } catch (error) {
      res.status(500).json({ error: 'Error fetching branches', details: error.message });
    }
  });

// POST endpoint to add a new rating and review
router.post('/addRating', async (req, res) => {
  try {
    const { rating, review, userId } = req.body;

    // Validation check
    if (!rating || !review || !userId) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Create a new rating
    const newRating = new Rating({
      rating,
      review,
      userId,
    });

    // Save the rating in the database
    await newRating.save();

    res.status(201).json({ message: 'Rating added successfully', data: newRating });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
