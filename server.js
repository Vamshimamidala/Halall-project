const express = require('express');
const mongoose = require('mongoose');
const menuRoutes = require('./routes/manageMenu'); // Menu routes
const restaurantFeaturesRoutes = require('./routes/restaurantFeaturesRoutes'); // Restaurant features routes
const manageBranchesRoutes = require('./routes/manageBranches');
const manageRestaurantRoutes = require('./routes/manageRestaurantRoutes');
const manageProductRoutes = require('./routes/manageProductRoutes');
const auth = require('./routes/auth');
const ratingRoutes = require('./routes/ratingRoutes');
const notifications = require('./routes/notificationRoutes')
const app = express();
const port = 3000;

app.use(express.json());

// Connect to MongoDB
mongoose.connect('mongodb+srv://vamshimamidala12:1ZgxEe9F2cmTRk5I@cluster0.f1nlu.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0').then(() => {
  console.log('Connected to MongoDB');
}).catch((error) => {
  console.error('Error connecting to MongoDB:', error);
});

// Use the routes
app.use(menuRoutes);
app.use(restaurantFeaturesRoutes);
app.use(manageBranchesRoutes);
app.use(manageRestaurantRoutes);
app.use(manageProductRoutes);
app.use(auth);
app.use(ratingRoutes);
app.use(notifications);

// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
