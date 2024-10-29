// models/Rating.js
const mongoose = require('mongoose');

// Define the Rating schema
const ratingSchema = new mongoose.Schema({
  rating: {
    type: Number,
    required: true,
    min: 1,
    max: 5, // Assuming a 1-5 rating scale
  },
  review: {
    type: String,
    required: true,
    maxlength: 500, // Limiting the review text length
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', // Assuming there is a User model
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now,
  }
});

const Rating = mongoose.model('Rating', ratingSchema);
module.exports = Rating;
