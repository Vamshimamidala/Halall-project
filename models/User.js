const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  businessName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  contactNumber: { type: String, required: true },
  address: { type: String, required: true },
  city: { type: String, required: true },
  postalCode: { type: String, required: true },
  password: { type: String, required: true },
  file: { type: String },
});

module.exports = mongoose.model('User', UserSchema);
