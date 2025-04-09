require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 10000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// MongoDB Connection
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('MongoDB connected successfully');
  } catch (err) {
    console.error('MongoDB connection error:', err.message);
    process.exit(1);
  }
};

// Define User Schema
const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
  role: {
    type: String,
    enum: ['user', 'organizer', 'admin'],
    default: 'user'
  },
  dateJoined: {
    type: Date,
    default: Date.now
  }
});

// Define Event Schema
const EventSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true
  },
  description: {
    type: String,
    required: true
  },
  date: {
    type: Date,
    required: true
  },
  location: {
    venueName: String,
    address: String
  },
  capacity: {
    maximum: Number,
    currentRegistrations: {
      type: Number,
      default: 0
    }
  },
  pricing: {
    amount: Number,
    currency: {
      type: String,
      default: 'TRY'
    }
  },
  host: {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    name: String
  },
  status: {
    type: String,
    enum: ['draft', 'open', 'full', 'cancelled', 'completed'],
    default: 'open'
  },
  participants: [{
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    name: String,
    status: {
      type: String,
      enum: ['registered', 'attended', 'cancelled'],
      default: 'registered'
    }
  }]
});

// Define Question Schema
const QuestionSchema = new mongoose.Schema({
  question: {
    type: String,
    required: true
  },
  category: {
    type: String,
    required: true
  },
  difficulty: {
    type: Number,
    min: 1,
    max: 5,
    default: 3
  },
  followUp: String,
  eventId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Event'
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Create models
const User = mongoose.model('User', UserSchema);
const Event = mongoose.model('Event', EventSchema);
const Question = mongoose.model('Question', QuestionSchema);

// Auth middleware
const auth = async (req, res, next) => {
  try {
    const token = req.header('x-auth-token');
    
    if (!token) {
      return res.status(401).json({ msg: 'No token, authorization denied' });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'entalk_jwt_secret_key_production');
    req.user = decoded.user;
    next();
  } catch (err) {
    res.status(401).json({ msg: 'Token is not valid' });
  }
};

// Routes

// Register User
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    // Check if user exists
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ msg: 'User already exists' });
    }
    
    // Create new user
    user = new User({
      name,
      email,
      password
    });
    
    // Hash password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);
    
    // Save user
    await user.save();
    
    // Create JWT
    const payload = {
      user: {
        id: user.id,
        role: user.role
      }
    };
    
    jwt.sign(
      payload,
      process.env.JWT_SECRET || 'entalk_jwt_secret_key_production',
      { expiresIn: '7d' },
      (err, token) => {
        if (err) throw err;
        res.json({ token });
      }
    );
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Login User
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Check if user exists
    let user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ msg: 'Invalid credentials' });
    }
    
    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ msg: 'Invalid credentials' });
    }
    
    // Create JWT
    const payload = {
      user: {
        id: user.id,
        role: user.role
      }
    };
    
    jwt.sign(
      payload,
      process.env.JWT_SECRET || 'entalk_jwt_secret_key_production',
      { expiresIn: '7d' },
      (err, token) => {
        if (err) throw err;
        res.json({ token });
      }
    );
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Get current user
app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Get all events
app.get('/api/events', async (req, res) => {
  try {
    const events = await Event.find().sort({ date: 1 });
    res.json(events);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Get event by ID
app.get('/api/events/:id', async (req, res) => {
  try {
    const event = await Event.findById(req.params.id);
    
    if (!event) {
      return res.status(404).json({ msg: 'Event not found' });
    }
    
    res.json(event);
  } catch (err) {
    console.error(err.message);
    if (err.kind === 'ObjectId') {
      return res.status(404).json({ msg: 'Event not found' });
    }
    res.status(500).send('Server error');
  }
});

// Create event
app.post('/api/events', auth, async (req, res) => {
  try {
    const { title, description, date, location, capacity, pricing } = req.body;
    
    const user = await User.findById(req.user.id).select('-password');
    
    const newEvent = new Event({
      title,
      description,
      date,
      location,
      capacity,
      pricing,
      host: {
        userId: req.user.id,
        name: user.name
      }
    });
    
    const event = await newEvent.save();
    res.json(event);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Generate questions with OpenAI
app.post('/api/questions/generate', auth, async (req, res) => {
  try {
    const { topic, difficulty, count } = req.body;
    
    // Mock questions for simplified version
    const mockQuestions = [
      {
        question: "What's your favorite way to practice a new language?",
        category: topic || "Language Learning",
        difficulty: difficulty || 3,
        followUp: "How often do you practice this way?"
      },
      {
        question: "Do you think it's better to learn grammar rules first or just start speaking?",
        category: topic || "Language Learning",
        difficulty: difficulty || 3,
        followUp: "Why do you prefer that approach?"
      },
      {
        question: "What's the most challenging aspect of learning English for you?",
        category: topic || "Language Learning",
        difficulty: difficulty || 3,
        followUp: "How do you overcome this challenge?"
      },
      {
        question: "If you could speak any language fluently instantly, which would you choose?",
        category: topic || "Language Learning",
        difficulty: difficulty || 2,
        followUp: "What would you do with this new skill?"
      },
      {
        question: "How has learning English changed your perspective on the world?",
        category: topic || "Language Learning",
        difficulty: difficulty || 4,
        followUp: "Can you give a specific example?"
      }
    ];
    
    // Return a subset of mock questions based on count
    const numQuestions = count || 3;
    const questions = mockQuestions.slice(0, Math.min(numQuestions, mockQuestions.length));
    
    res.json({ success: true, questions });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Save question
app.post('/api/questions', auth, async (req, res) => {
  try {
    const { question, category, difficulty, followUp, eventId } = req.body;
    
    const newQuestion = new Question({
      question,
      category,
      difficulty,
      followUp,
      eventId,
      createdBy: req.user.id
    });
    
    const savedQuestion = await newQuestion.save();
    res.json(savedQuestion);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Get questions for event
app.get('/api/questions/event/:eventId', auth, async (req, res) => {
  try {
    const questions = await Question.find({ eventId: req.params.eventId });
    res.json(questions);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Simple welcome page for root route
app.get('/', (req, res) => {
  res.send(`
    <html>
      <head>
        <title>EnTalk Questions Tool</title>
        <style>
          body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            line-height: 1.6;
          }
          h1 {
            color: #1976d2;
          }
          .container {
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 20px;
            margin-top: 20px;
          }
        </style>
      </head>
      <body>
        <h1>EnTalk Questions Tool</h1>
        <div class="container">
          <h2>Welcome to EnTalk Questions Tool!</h2>
          <p>This is the API server for the EnTalk Questions Tool application.</p>
          <p>API endpoints available:</p>
          <ul>
            <li>/api/auth/register - Register a new user</li>
            <li>/api/auth/login - Login a user</li>
            <li>/api/auth/me - Get current user</li>
            <li>/api/events - Get all events</li>
            <li>/api/events/:id - Get event by ID</li>
            <li>/api/questions/generate - Generate questions with OpenAI</li>
            <li>/api/questions - Save a question</li>
            <li>/api/questions/event/:eventId - Get questions for an event</li>
          </ul>
          <p>Status: Server is running</p>
          <p>MongoDB Connection: ${mongoose.connection.readyState ? 'Connected' : 'Disconnected'}</p>
          <p>Environment: ${process.env.NODE_ENV || 'development'}</p>
          <p>Render.com Deployment: Active</p>
        </div>
      </body>
    </html>
  `);
});

// Health check endpoint for Render
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', message: 'EnTalk Questions Tool API is running' });
});

// Connect to MongoDB and start server
connectDB().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
  });
});
