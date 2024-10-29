const express = require('express');
const router = express.Router();
const RestaurantFeatures = require('../models/restaurantFeatures'); // Import RestaurantFeatures model

router.get('/features', async (req, res) => {
  try {
    const newFeature = await RestaurantFeatures.find(); // Fetch all features from the database
    res.status(200).json(newFeature); // Send the retrieved features as a response
  } catch (error) {
    res.status(500).json({ error: 'Error fetching feature', details: error.message });
  }
});
// Create a new restaurant feature
router.post('/features', async (req, res) => {
  const { serviceName, image, status } = req.body;

  try {
    const newFeature = new RestaurantFeatures({ serviceName, image, status });
    await newFeature.save();
    res.status(201).json(newFeature);
  } catch (error) {
    res.status(500).json({ error: 'Error saving feature' });
  }
});

// Update a restaurant feature by ID
router.put('/features/:id', async (req, res) => {
  const featureId = req.params.id;
  const updatedData = req.body;

  try {
    const updatedFeature = await RestaurantFeatures.findByIdAndUpdate(featureId, updatedData, { new: true });
    if (!updatedFeature) {
      return res.status(404).send({ message: 'Feature not found' });
    }
    res.send(updatedFeature);
  } catch (err) {
    res.status(500).send(err);
  }
});

// Delete a restaurant feature by ID
router.delete('/features/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const deletedFeature = await RestaurantFeatures.findByIdAndDelete(id);

    if (!deletedFeature) {
      return res.status(404).json({ message: 'Feature not found' });
    }

    res.status(200).json({ message: 'Feature deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting feature', error });
  }
});

module.exports = router;
