# PassportJs
A comprehensive guide/cheatsheet for learning passportjs
# Complete PassportJS Learning Guide & Cheatsheet

## Table of Contents
1. [What is PassportJS?](#what-is-passportjs)
2. [Installation & Setup](#installation--setup)
3. [Core Concepts](#core-concepts)
4. [Basic Configuration](#basic-configuration)
5. [Local Authentication](#local-authentication)
6. [OAuth Strategies](#oauth-strategies)
7. [Session Management](#session-management)
8. [Middleware & Route Protection](#middleware--route-protection)
9. [Common Patterns](#common-patterns)
10. [Error Handling](#error-handling)
11. [Testing](#testing)
12. [Best Practices](#best-practices)
13. [Troubleshooting](#troubleshooting)
14. [Quick Reference](#quick-reference)

## What is PassportJS?

PassportJS is a simple, unobtrusive authentication middleware for Node.js that supports 500+ authentication strategies including:
- Local (username/password)
- OAuth (Google, Facebook, Twitter, GitHub)
- OpenID Connect
- SAML
- JWT

**Key Features:**
- Strategy-based authentication
- Lightweight and modular
- Easy integration with Express.js
- Extensive ecosystem of strategies

## Installation & Setup

### Basic Installation
```bash
npm install passport
npm install express-session  # Required for session support
```

### Strategy-Specific Packages
```bash
# Local authentication
npm install passport-local bcrypt

# OAuth strategies
npm install passport-google-oauth20
npm install passport-facebook
npm install passport-github2
npm install passport-twitter

# JWT strategy
npm install passport-jwt jsonwebtoken
```

## Core Concepts

### 1. Strategies
Authentication mechanisms that define how to authenticate users.

### 2. Serialization/Deserialization
Process of storing and retrieving user information from sessions.

### 3. Middleware
Functions that process authentication requests.

### 4. Verification Callbacks
Functions that verify credentials and return user data.

## Basic Configuration

### Express App Setup
```javascript
const express = require('express');
const session = require('express-session');
const passport = require('passport');

const app = express();

// Middleware setup
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Session configuration
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: false, // Set to true in production with HTTPS
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Serialization
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  // Fetch user from database by id
  User.findById(id, (err, user) => {
    done(err, user);
  });
});
```

## Local Authentication

### Strategy Configuration
```javascript
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');

passport.use(new LocalStrategy({
  usernameField: 'email', // Default is 'username'
  passwordField: 'password'
}, async (email, password, done) => {
  try {
    // Find user in database
    const user = await User.findOne({ email });
    
    if (!user) {
      return done(null, false, { message: 'User not found' });
    }
    
    // Verify password
    const isValid = await bcrypt.compare(password, user.password);
    
    if (!isValid) {
      return done(null, false, { message: 'Incorrect password' });
    }
    
    return done(null, user);
  } catch (error) {
    return done(error);
  }
}));
```

### Routes
```javascript
// Login route
app.post('/login', 
  passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
    failureFlash: true
  })
);

// Alternative with custom callback
app.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) return next(err);
    if (!user) return res.status(401).json({ message: info.message });
    
    req.logIn(user, (err) => {
      if (err) return next(err);
      return res.json({ message: 'Login successful', user });
    });
  })(req, res, next);
});

// Registration route
app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
    // Create user
    const user = new User({
      email,
      password: hashedPassword
    });
    
    await user.save();
    res.json({ message: 'Registration successful' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Logout route
app.post('/logout', (req, res) => {
  req.logout((err) => {
    if (err) return next(err);
    res.json({ message: 'Logged out successfully' });
  });
});
```

## OAuth Strategies

### Google OAuth 2.0
```javascript
const GoogleStrategy = require('passport-google-oauth20').Strategy;

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
  try {
    // Check if user exists
    let user = await User.findOne({ googleId: profile.id });
    
    if (user) {
      return done(null, user);
    }
    
    // Create new user
    user = await User.create({
      googleId: profile.id,
      email: profile.emails[0].value,
      name: profile.displayName,
      avatar: profile.photos[0].value
    });
    
    return done(null, user);
  } catch (error) {
    return done(error, null);
  }
}));

// Routes
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    res.redirect('/dashboard');
  }
);
```

### GitHub OAuth
```javascript
const GitHubStrategy = require('passport-github2').Strategy;

passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: "/auth/github/callback"
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ githubId: profile.id });
    
    if (user) {
      return done(null, user);
    }
    
    user = await User.create({
      githubId: profile.id,
      username: profile.username,
      email: profile.emails?.[0]?.value,
      name: profile.displayName,
      avatar: profile.photos[0].value
    });
    
    return done(null, user);
  } catch (error) {
    return done(error, null);
  }
}));
```

## Session Management

### Session Store Configuration
```javascript
const MongoStore = require('connect-mongo');

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    touchAfter: 24 * 3600 // Lazy session update
  }),
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24 * 7 // 7 days
  }
}));
```

### Session Methods
```javascript
// Check if user is authenticated
req.isAuthenticated() // returns boolean

// Access current user
req.user // user object if authenticated

// Manual login
req.logIn(user, callback)

// Manual logout
req.logOut(callback)
```

## Middleware & Route Protection

### Authentication Middleware
```javascript
// Basic authentication check
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ message: 'Authentication required' });
}

// Role-based authorization
function ensureRole(role) {
  return (req, res, next) => {
    if (req.isAuthenticated() && req.user.role === role) {
      return next();
    }
    res.status(403).json({ message: 'Insufficient permissions' });
  };
}

// Multiple roles
function ensureRoles(roles) {
  return (req, res, next) => {
    if (req.isAuthenticated() && roles.includes(req.user.role)) {
      return next();
    }
    res.status(403).json({ message: 'Insufficient permissions' });
  };
}
```

### Protected Routes
```javascript
// Single protected route
app.get('/dashboard', ensureAuthenticated, (req, res) => {
  res.json({ user: req.user });
});

// Admin only routes
app.get('/admin', ensureRole('admin'), (req, res) => {
  res.json({ message: 'Admin dashboard' });
});

// Multiple role access
app.get('/moderator', ensureRoles(['admin', 'moderator']), (req, res) => {
  res.json({ message: 'Moderator panel' });
});
```

## Common Patterns

### Custom Serialization
```javascript
// Store minimal user data in session
passport.serializeUser((user, done) => {
  done(null, { id: user.id, role: user.role });
});

passport.deserializeUser(async (sessionUser, done) => {
  try {
    const user = await User.findById(sessionUser.id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});
```

### Multiple Strategies
```javascript
// Allow both local and OAuth login
app.post('/auth/login',
  passport.authenticate(['local', 'oauth'], {
    successRedirect: '/dashboard',
    failureRedirect: '/login'
  })
);
```

### Custom Strategy
```javascript
const passport = require('passport-strategy');

class CustomStrategy extends passport.Strategy {
  constructor(options, verify) {
    super();
    this.name = 'custom';
    this._verify = verify;
    this._options = options;
  }
  
  authenticate(req, options) {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
      return this.fail('No token provided');
    }
    
    // Verify token logic here
    this._verify(token, (err, user) => {
      if (err) return this.error(err);
      if (!user) return this.fail('Invalid token');
      return this.success(user);
    });
  }
}

passport.use(new CustomStrategy({}, (token, done) => {
  // Token verification logic
}));
```

## Error Handling

### Strategy Error Handling
```javascript
passport.use(new LocalStrategy(async (username, password, done) => {
  try {
    const user = await User.findOne({ username });
    
    if (!user) {
      return done(null, false, { 
        message: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }
    
    const isValid = await bcrypt.compare(password, user.password);
    
    if (!isValid) {
      return done(null, false, { 
        message: 'Invalid password',
        code: 'INVALID_PASSWORD'
      });
    }
    
    return done(null, user);
  } catch (error) {
    return done(error);
  }
}));
```

### Global Error Handler
```javascript
app.use((err, req, res, next) => {
  console.error(err.stack);
  
  if (err.name === 'AuthenticationError') {
    return res.status(401).json({ 
      error: 'Authentication failed',
      message: err.message 
    });
  }
  
  res.status(500).json({ 
    error: 'Internal server error' 
  });
});
```

## Testing

### Testing Authentication
```javascript
const request = require('supertest');
const app = require('../app');

describe('Authentication', () => {
  test('should login with valid credentials', async () => {
    const response = await request(app)
      .post('/login')
      .send({
        email: 'test@example.com',
        password: 'password123'
      });
    
    expect(response.status).toBe(200);
    expect(response.body.user).toBeDefined();
  });
  
  test('should protect authenticated routes', async () => {
    const response = await request(app)
      .get('/dashboard');
    
    expect(response.status).toBe(401);
  });
});
```

### Mocking Passport
```javascript
// Test helper
function mockUser(user) {
  return (req, res, next) => {
    req.user = user;
    req.isAuthenticated = () => true;
    next();
  };
}

// In tests
app.use('/test', mockUser({ id: 1, role: 'admin' }));
```

## Best Practices

### Security
```javascript
// 1. Use HTTPS in production
app.use(session({
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'strict'
  }
}));

// 2. Strong session secrets
const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex');

// 3. Rate limiting
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts
  message: 'Too many login attempts'
});

app.post('/login', loginLimiter, passport.authenticate('local'));

// 4. Input validation
const { body, validationResult } = require('express-validator');

app.post('/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 })
], (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
}, passport.authenticate('local'));
```

### Performance
```javascript
// 1. Efficient session storage
const RedisStore = require('connect-redis')(session);
const redis = require('redis');
const client = redis.createClient();

app.use(session({
  store: new RedisStore({ client }),
  // ... other options
}));

// 2. Selective user data loading
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id).select('-password -__v');
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});
```

## Troubleshooting

### Common Issues

#### 1. "Failed to serialize user into session"
```javascript
// Make sure you have serializeUser configured
passport.serializeUser((user, done) => {
  done(null, user.id); // or user._id for MongoDB
});
```

#### 2. "req.user is undefined"
```javascript
// Ensure middleware order is correct:
app.use(session({ /* config */ }));
app.use(passport.initialize());
app.use(passport.session()); // Must come after session middleware
```

#### 3. OAuth callback errors
```javascript
// Check callback URL matches exactly in OAuth provider settings
// Ensure environment variables are set correctly
console.log('Callback URL:', process.env.GOOGLE_CALLBACK_URL);
```

#### 4. Sessions not persisting
```javascript
// Check session configuration
app.use(session({
  secret: 'your-secret',
  resave: false,           // Don't save session if unmodified
  saveUninitialized: false // Don't create session until something stored
}));
```

## Quick Reference

### Essential Methods
```javascript
// Authentication
req.isAuthenticated()     // Check if user is logged in
req.user                  // Current user object
req.logIn(user, callback) // Manual login
req.logOut(callback)      // Manual logout

// Strategy registration
passport.use(strategy)

// Serialization
passport.serializeUser(callback)
passport.deserializeUser(callback)

// Authentication middleware
passport.authenticate('strategy', options)
passport.initialize()
passport.session()
```

### Common Strategies
```javascript
// Local
const LocalStrategy = require('passport-local').Strategy;

// OAuth
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const TwitterStrategy = require('passport-twitter').Strategy;

// JWT
const JwtStrategy = require('passport-jwt').Strategy;
```

### Session Configuration Template
```javascript
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: new MongoStore({
    mongoUrl: process.env.MONGODB_URI
  }),
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000
  }
}));
```

### Environment Variables Template
```bash
# Session
SESSION_SECRET=your-super-secret-key-here

# Database
MONGODB_URI=mongodb://localhost:27017/your-app

# OAuth - Google
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# OAuth - GitHub
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# JWT
JWT_SECRET=your-jwt-secret
```

---

## Resources

- **Official Documentation**: [PassportJS Docs](http://www.passportjs.org/docs/)
- **Strategy List**: [PassportJS Strategies](http://www.passportjs.org/packages/)
- **GitHub Repository**: [PassportJS GitHub](https://github.com/jaredhanson/passport)

This guide covers the essential concepts and patterns you need to implement authentication with PassportJS. Start with local authentication, then gradually add OAuth providers and advanced features as needed.
