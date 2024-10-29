const mongoose = require('mongoose');

const notificationSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// Define the model
const notifications = mongoose.model('notifications', notificationSchema);

module.exports = notifications;
