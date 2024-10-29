// models/manageRestaurant.js

const mongoose = require('mongoose');

const locationSchema = new mongoose.Schema({
  location: { type: String, required: true },
  latitude: { type: Number, required: true },
  longitude: { type: Number, required: true },
  city: { type: String, required: true },
  state: { type: String, required: true },
  country: { type: String, required: true },
  postalCode: { type: String, required: true },
});

const uploadFilesSchema = new mongoose.Schema({
  restaurantLogo: { type: String, required: true },
  certificationDocument: { type: String, required: true },
  image: { type: String, required: true },
});

const otherDetailsSchema = new mongoose.Schema({
  halalPercentage: { type: Number, required: true },
  status: { type: String, enum: ['approve', 'pending', 'block', 'closed'], required: true },
  subscription: { type: String, required: true },
  halalStatus: { type: String, enum: ['yes', 'no', 'partially'], required: true },
  deliversRecipe: { type: Boolean, required: true }, // Assuming yes/no as a boolean
  deliveryLink: { type: String, required: true },
  showHideMenuItem: { type: String, enum: ['show', 'hide'], required: true },
  description: { type: String, required: true },
  explanatoryMessage: { type: String, required: true },
  restaurantTags: { type: [String], required: true },
  restaurantFeatures: { type: [String], required: true },
});

const personalInfoSchema = new mongoose.Schema({
  contactPersonName: { type: String, required: true },
  contactPersonEmail: { type: String, required: true },
});

const restaurantTimingSchema = new mongoose.Schema({
  day: { type: String, required: true },
  status: { type: String, enum: ['open', 'closed'], required: true },
  open: { type: String, required: true }, // Format: HH:mm
  close: { type: String, required: true }, // Format: HH:mm
});

// Main Restaurant Schema
const restaurantSchema = new mongoose.Schema({
  category: { type: String, required: true },
  name: { type: String, required: true },
  contact: { type: String, required: true },
  email: { type: String, required: true },
  location: locationSchema,
  uploadFiles: uploadFilesSchema,
  otherDetails: otherDetailsSchema,
  personalInformation: personalInfoSchema,
  restaurantTiming: [restaurantTimingSchema], // Array of objects for multiple days
});

// Export the Restaurant model
module.exports = mongoose.model('ManageRestaurant', restaurantSchema);
