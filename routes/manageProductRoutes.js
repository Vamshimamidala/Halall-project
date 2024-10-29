// routes/manageProductRoutes.js

const express = require('express');
const ManageProduct = require('../models/manageProduct'); // Import the ManageProduct model

const router = express.Router();

// Get the count of all products
router.get('/product/count', async (req, res) => {
  try {
    const count = await ManageProduct.countDocuments();
    res.status(200).json({ count });
  } catch (error) {
    res.status(500).json({ error: 'Error fetching product count', details: error.message });
  }
});

//Get all products
router.get('/product', async (req, res) => {
  try {
    const products = await ManageProduct.find(); // Fetch all products from the database
    res.status(200).json(products); // Send the products as a response
  } catch (error) {
    res.status(500).json({ error: 'Error retrieving products', details: error.message });
  }
});

// Create a new product
router.post('/product', async (req, res) => {
  const {
    menu,
    productName,
    productPrice,
    status,
    productImage,
    halalStatus,
    productUPC,
    productDescription,
    ingredients,
    carbs,
    saturatedFatForCarbs,
    transFatForCarbs,
    protein,
    fat,
    saturatedFatForFat,
    transFatForFat,
  } = req.body;

  try {
    const newProduct = new ManageProduct({
      menu,
      productName,
      productPrice,
      status,
      productImage,
      halalStatus,
      productUPC,
      productDescription,
      ingredients,
      carbs,
      saturatedFatForCarbs,
      transFatForCarbs,
      protein,
      fat,
      saturatedFatForFat,
      transFatForFat,
    });

    await newProduct.save();
    res.status(201).json(newProduct);
  } catch (error) {
    res.status(500).json({ error: 'Error saving product', details: error.message });
  }
});

// Update a product by ID
router.put('/product/:id', async (req, res) => {
  const productId = req.params.id;
  const updatedData = req.body;

  try {
    const updatedProduct = await ManageProduct.findByIdAndUpdate(productId, updatedData, { new: true });

    if (!updatedProduct) {
      return res.status(404).json({ message: 'Product not found' });
    }

    res.status(200).json(updatedProduct);
  } catch (error) {
    res.status(500).json({ error: 'Error updating product', details: error.message });
  }
});

// Delete a product by ID
router.delete('/product/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const deletedProduct = await ManageProduct.findByIdAndDelete(id);

    if (!deletedProduct) {
      return res.status(404).json({ message: 'Product not found' });
    }

    res.status(200).json({ message: 'Product deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting product', details: error.message });
  }
});

// Export the router
module.exports = router;
