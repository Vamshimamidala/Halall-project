// models/manageProduct.js

const mongoose = require('mongoose');

const productSchema = new mongoose.Schema({
  menu: { type: String, required: true },
  productName: { type: String, required: true },
  productPrice: { type: Number, required: true },
  status: { type: String, enum: ['available', 'unavailable'], required: true },
  productImage: { type: String, required: true },
  halalStatus: { type: String, enum: ['yes', 'no', 'partially'], required: true },
  productUPC: { type: String, required: true },
  productDescription: { type: String, required: true },
  ingredients: { type: [String], required: true },
  carbs: { type: Number, required: true },
  saturatedFatForCarbs: { type: Number, required: true },
  transFatForCarbs: { type: Number, required: true },
  protein: { type: Number, required: true },
  fat: { type: Number, required: true },
  saturatedFatForFat: { type: Number, required: true },
  transFatForFat: { type: Number, required: true },
});

// Export the Product model
module.exports = mongoose.model('ManageProduct', productSchema);
