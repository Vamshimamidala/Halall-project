const mongoose = require('mongoose');

const locationSchema = new mongoose.Schema({
  location: { type: String, required: true },
  longitude: { type: Number, required: true },
  latitude: { type: Number, required: true },
  city: { type: String, required: true },
  state: { type: String, required: true },
  country: { type: String, required: true },
  postalCode: { type: String, required: true },
});

const uploadsSchema = new mongoose.Schema({
  restaurantLogo: { type: String, required: true },
  image: { type: String, required: true },
  certificationDocument: { type: String, required: true },
});

const otherDetailsSchema = new mongoose.Schema({
  halalPercentage: { type: Number, required: true },
  status: {
    type: String,
    enum: ['approve', 'pending', 'block', 'closed'],
    required: true,
  },
  showHideMenuItem: {
    type: String,
    enum: ['show', 'hide'],
    required: true,
  },
  deliversRecipe: {
    type: String,
    enum: ['yes', 'no'],
    required: true,
  },
  deliveryLink: { type: String, required: true },
  halalStatus: {
    type: String,
    enum: ['yes', 'no', 'partially'],
    required: true,
  },
});

const restaurantTimingSchema = new mongoose.Schema({
  days: { type: String, required: true }, // You can change this to an array if you want multiple days
  status: {
    type: String,
    enum: ['open', 'closed'],
    required: true,
  },
  openTime: { type: String, required: true }, // Format: HH:mm
  closedTime: { type: String, required: true }, // Format: HH:mm
});

const manageBranchSchema = new mongoose.Schema({
  category: { type: String, required: true },
  name: { type: String, required: true },
  contactNumber: { type: String, required: true },
  email: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true }, // Remember to hash passwords before saving
  confirmPassword: { type: String, required: true }, // Handle confirmPassword validation in your logic
  location: locationSchema,
  uploads: uploadsSchema,
  otherDetails: otherDetailsSchema,
  description: { type: String, required: true },
  explanatoryMessage: { type: String, required: true },
  restaurantTags: { type: [String], required: true }, // Array of tags
  restaurantFeatures: { type: [String], required: true }, // Array of features
  restaurantTiming: restaurantTimingSchema,
});

// Export the model
const ManageBranch = mongoose.model('ManageBranch', manageBranchSchema);
module.exports = ManageBranch;
