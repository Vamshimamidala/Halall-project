const express = require('express');
const router = express.Router();
const ManageMenu = require('../models/manageMenu'); // Import your ManageMenu model




// Count all menu items
router.get('/menu/count', async (req, res) => {
    try {
      const count = await ManageMenu.countDocuments(); // Count all documents in the ManageMenu collection
      res.status(200).json({ count }); // Return the count in JSON format
    } catch (error) {
      res.status(500).json({ error: 'Error counting menu items', details: error.message });
    }
  });

  
// GET all menus
router.get('/menu', async (req, res) => {
    try {
      const menus = await ManageMenu.find(); // Fetch all menus from the database
      res.status(200).json(menus); // Send the retrieved menus as a response
    } catch (error) {
      res.status(500).json({ error: 'Error fetching menus', details: error.message });
    }
  });


// Create a new menu
router.post('/menu', async (req, res) => {
    const { menuName, menuImage, status } = req.body;
    
    try {
        const newMenu = new ManageMenu({ menuName, menuImage, status });
        await newMenu.save();
        res.status(201).json(newMenu);
    } catch (error) {
        res.status(500).json({ error: 'Error saving menu' });
    }
});

// Update a menu by ID
router.put('/menu/:id', async (req, res) => {
    const menuId = req.params.id;
    const updatedData = req.body;

    try {
        const updatedMenu = await ManageMenu.findByIdAndUpdate(menuId, updatedData, { new: true });
        if (!updatedMenu) {
            return res.status(404).send({ message: 'Menu item not found' });
        }
        res.send(updatedMenu);
    } catch (err) {
        res.status(500).send(err);
    }
});

// Delete a menu by ID
router.delete('/menu/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const deletedMenu = await ManageMenu.findByIdAndDelete(id);

        if (!deletedMenu) {
            return res.status(404).json({ message: 'Menu not found' });
        }

        res.status(200).json({ message: 'Menu deleted successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error deleting menu', error });
    }
});

module.exports = router;
