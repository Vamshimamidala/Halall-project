const mongoose = require('mongoose');

// Create the ManageMenu schema
const manageMenuSchema = new mongoose.Schema({
  menuName: {
    type: String,
    required: true, // The menu name is required
    trim: true
  },
  menuImage: {
    type: String,
    required: true, // The menu image is required
    trim: true
  },
  status: {
    type: String,
    enum: ['active', 'inactive'], // Only 'active' and 'inactive' are allowed
    default: 'active', // Default value is 'inactive'
    required: true
  }
});

// Create and export the ManageMenu model
const ManageMenu = mongoose.model('ManageMenu', manageMenuSchema);
module.exports = ManageMenu;
