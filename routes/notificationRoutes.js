const express = require('express');
const notifications = require('../models/notifications'); // Import the Notification model

const router = express.Router();

// GET all notifications
router.get('/notification', async (req, res) => {
    try {
      const allNotifications = await notifications.find(); // Fetch all notifications from the database
      res.status(200).json(allNotifications); // Send the retrieved notifications as a response
    } catch (error) {
      res.status(500).json({ error: 'Error fetching notifications', details: error.message });
    }
});

// POST endpoint to add a new notification
router.post('/notification', async (req, res) => {
  try {
    const { name } = req.body;

    // Validation check
    if (!name) {
      return res.status(400).json({ error: 'Name field is required' });
    }

    // Create a new notification
    const newNotification = new notifications({
      name
    });

    // Save the notification in the database
    await newNotification.save();

    res.status(201).json({ message: 'Notification added successfully', data: newNotification });
  } catch (error) {
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

module.exports = router;
