const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5500; // Changed to 5500 as per your setup

// Middleware
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    // Allow localhost and 127.0.0.1 on any port
    // Allow file:// protocol (direct HTML file opening)
    if (!origin || origin.includes('localhost') || origin.includes('127.0.0.1') || origin.startsWith('file://')) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/rms', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('✅ MongoDB connected successfully'))
.catch(err => {
  console.error('❌ MongoDB connection error:', err.message);
  console.log('💡 Make sure MongoDB is running on localhost:27017');
  process.exit(1);
});

// Models
const User = require('./models/User');
const Restaurant = require('./models/Restaurant');
const MenuItem = require('./models/MenuItem');
const Table = require('./models/Table');
const Booking = require('./models/Booking');
const Order = require('./models/Order');
const Feedback = require('./models/Feedback');
const Income = require('./models/Income');

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access token required' });

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Test route
app.get('/api/test', (req, res) => {
  res.json({
    message: '✅ Server is running correctly!',
    timestamp: new Date().toISOString(),
    port: PORT,
    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// Routes

// Auth routes
app.post('/api/auth/register', [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 }),
  body('name').trim().isLength({ min: 1 }),
  body('type').isIn(['user', 'restaurant'])
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { email, password, name, type } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    let restaurantId = null;
    if (type === 'restaurant') {
      // Create restaurant
      const restaurant = new Restaurant({
        name,
        email,
        logo: `https://ui-avatars.com/api/?name=${encodeURIComponent(name)}&background=101827&color=fff`
      });
      await restaurant.save();
      restaurantId = restaurant._id;
    }

    // Create user
    const user = new User({
      email,
      password: hashedPassword,
      name,
      type,
      restaurantId
    });
    await user.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.post('/api/auth/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').exists()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user._id, email: user.email, type: user.type, restaurantId: user.restaurantId },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        type: user.type,
        restaurantId: user.restaurantId
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Restaurant routes
app.get('/api/restaurants', async (req, res) => {
  try {
    const restaurants = await Restaurant.find().populate('menu').populate('tables');
    res.json(restaurants);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.get('/api/restaurants/:id', async (req, res) => {
  try {
    const restaurant = await Restaurant.findById(req.params.id)
      .populate('menu')
      .populate('tables')
      .populate('bookings')
      .populate('orders')
      .populate('feedback')
      .populate('incomes');
    if (!restaurant) {
      return res.status(404).json({ message: 'Restaurant not found' });
    }
    res.json(restaurant);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Menu routes
app.post('/api/restaurants/:restaurantId/menu', authenticateToken, async (req, res) => {
  try {
    if (req.user.type !== 'restaurant' || req.user.restaurantId !== req.params.restaurantId) {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    const { name, price, img } = req.body;
    const menuItem = new MenuItem({
      name,
      price,
      img,
      restaurant: req.params.restaurantId
    });
    await menuItem.save();

    await Restaurant.findByIdAndUpdate(req.params.restaurantId, {
      $push: { menu: menuItem._id }
    });

    res.status(201).json(menuItem);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.get('/api/restaurants/:restaurantId/menu', async (req, res) => {
  try {
    const menuItems = await MenuItem.find({ restaurant: req.params.restaurantId });
    res.json(menuItems);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Table routes
app.post('/api/restaurants/:restaurantId/tables', authenticateToken, async (req, res) => {
  try {
    if (req.user.type !== 'restaurant' || req.user.restaurantId !== req.params.restaurantId) {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    const { num, status } = req.body;
    const table = new Table({
      num,
      status,
      restaurant: req.params.restaurantId
    });
    await table.save();

    await Restaurant.findByIdAndUpdate(req.params.restaurantId, {
      $push: { tables: table._id }
    });

    res.status(201).json(table);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.get('/api/restaurants/:restaurantId/tables', async (req, res) => {
  try {
    const tables = await Table.find({ restaurant: req.params.restaurantId });
    res.json(tables);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Booking routes
app.post('/api/restaurants/:restaurantId/bookings', async (req, res) => {
  try {
    const { tableNum, start, end, userName } = req.body;
    const booking = new Booking({
      tableNum,
      start,
      end,
      userName,
      restaurant: req.params.restaurantId
    });
    await booking.save();

    await Restaurant.findByIdAndUpdate(req.params.restaurantId, {
      $push: { bookings: booking._id }
    });

    res.status(201).json(booking);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.get('/api/restaurants/:restaurantId/bookings', async (req, res) => {
  try {
    const bookings = await Booking.find({ restaurant: req.params.restaurantId });
    res.json(bookings);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Order routes
app.post('/api/restaurants/:restaurantId/orders', async (req, res) => {
  try {
    const { userName, items, total, method } = req.body;
    const order = new Order({
      userName,
      items,
      total,
      method,
      restaurant: req.params.restaurantId
    });
    await order.save();

    await Restaurant.findByIdAndUpdate(req.params.restaurantId, {
      $push: { orders: order._id }
    });

    res.status(201).json(order);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.get('/api/restaurants/:restaurantId/orders', async (req, res) => {
  try {
    const orders = await Order.find({ restaurant: req.params.restaurantId });
    res.json(orders);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Feedback routes
app.post('/api/restaurants/:restaurantId/feedback', async (req, res) => {
  try {
    const { userName, text, foodRating, serviceRating } = req.body;
    const feedback = new Feedback({
      userName,
      text,
      foodRating,
      serviceRating,
      restaurant: req.params.restaurantId
    });
    await feedback.save();

    await Restaurant.findByIdAndUpdate(req.params.restaurantId, {
      $push: { feedback: feedback._id }
    });

    res.status(201).json(feedback);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.get('/api/restaurants/:restaurantId/feedback', async (req, res) => {
  try {
    const feedback = await Feedback.find({ restaurant: req.params.restaurantId });
    res.json(feedback);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Income routes
app.post('/api/restaurants/:restaurantId/incomes', authenticateToken, async (req, res) => {
  try {
    if (req.user.type !== 'restaurant' || req.user.restaurantId !== req.params.restaurantId) {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    const { amount } = req.body;
    const income = new Income({
      amount,
      restaurant: req.params.restaurantId
    });
    await income.save();

    await Restaurant.findByIdAndUpdate(req.params.restaurantId, {
      $push: { incomes: income._id }
    });

    res.status(201).json(income);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.get('/api/restaurants/:restaurantId/incomes', authenticateToken, async (req, res) => {
  try {
    if (req.user.type !== 'restaurant' || req.user.restaurantId !== req.params.restaurantId) {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    const incomes = await Income.find({ restaurant: req.params.restaurantId });
    res.json(incomes);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
