const mongoose = require('mongoose');

// Define the RestaurantFeatures schema
const restaurantFeaturesSchema = new mongoose.Schema({
  serviceName: {
    type: String,
    required: true,
    trim: true
  },
  image: {
    type: String,
    required: true
  },
  status: {
    type: String,
    enum: ['active', 'inactive'], // Ensuring status can only be 'active' or 'inactive'
    default: 'active'
  }
});

// Create the RestaurantFeatures model
const RestaurantFeatures = mongoose.model('RestaurantFeatures', restaurantFeaturesSchema);

module.exports = RestaurantFeatures;
