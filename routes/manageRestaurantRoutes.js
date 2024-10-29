// routes/manageRestaurantRoutes.js

const express = require('express');
const ManageRestaurant = require('../models/manageRestaurant'); // Import the ManageRestaurant model

const router = express.Router();

// Create a new restaurant
router.post('/restaurant', async (req, res) => {
  const {
    category,
    name,
    contact,
    email,
    location,
    uploadFiles,
    otherDetails,
    personalInformation,
    restaurantTiming,
  } = req.body;

  try {
    const newRestaurant = new ManageRestaurant({
      category,
      name,
      contact,
      email,
      location,
      uploadFiles,
      otherDetails,
      personalInformation,
      restaurantTiming,
    });

    await newRestaurant.save();
    res.status(201).json(newRestaurant);
  } catch (error) {
    res.status(500).json({ error: 'Error saving restaurant', details: error.message });
  }
});

// Export the router
module.exports = router;
