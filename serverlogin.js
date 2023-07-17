const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MongoDBStore = require('connect-mongodb-session')(session);
const mongoose = require('mongoose');

const app = express();
app.use(express.json());

// Connect to MongoDB
mongoose.connect('mongodb://localhost/house_rental_app', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB');
});

// User schema and model
const userSchema = new mongoose.Schema({
  email: { type: String, required: true },
  phone: { type: String, required: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  verified: { type: Boolean, default: false },
  verificationCode: { type: String },
  resetPasswordToken: { type: String },
  resetPasswordTokenExpiry: { type: Date },
  loginAttempts: { type: Number, default: 0 },
  lockUntil: { type: Date },
});
const User = mongoose.model('User', userSchema);

// Configure session store
const store = new MongoDBStore({
  uri: 'mongodb://localhost/house_rental_app',
  collection: 'sessions',
});

// Session middleware
app.use(
  session({
    secret: 'house_rental_app_secret',
    resave: false,
    saveUninitialized: false,
    store: store,
    cookie: { secure: false }, // Set to true if using HTTPS
  })
);

// Authentication middleware
const requireAuth = (req, res, next) => {
  if (req.session.userId) {
    next();
  } else {
    res.status(401).json({ message: 'Unauthorized' });
  }
};

// User Registration Endpoint
app.post('/api/register', async (req, res) => {
  const { email, phone, password } = req.body;

  try {
    // Check if user already exists
    const existingUser = await User.findOne().or([{ email }, { phone }]);
    if (existingUser) {
      return res.status(409).json({ message: 'User already exists' });
    }

    // Generate a hashed password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create the user in the database
    const newUser = new User({ email, phone, password: hashedPassword });
    await newUser.save();

    return res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

// User Login Endpoint
app.post('/api/login', async (req, res) => {
  const { emailOrPhone, password } = req.body;

  try {
    // Find the user in the database by email or phone
    const user = await User.findOne().or([{ email: emailOrPhone }, { phone: emailOrPhone }]);
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Check if the account is locked
    if (user.lockUntil && user.lockUntil > Date.now()) {
      return res.status(401).json({ message: 'Account locked. Please try again later.' });
    }

    // Compare the provided password with the hashed password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      // Increment login attempts
      user.loginAttempts += 1;
      await user.save();

      // Lock the account after a certain number of failed attempts
      if (user.loginAttempts >= 5) {
        user.lockUntil = new Date(Date.now() + 2 * 60 * 60 * 1000); // Lock the account for 2 hours
        user.loginAttempts = 0;
        await user.save();
        return res.status(401).json({ message: 'Account locked. Please try again later.' });
      }

      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Reset login attempts if login is successful
    user.loginAttempts = 0;
    user.lockUntil = null;
    await user.save();

    // Store the user ID in the session
    req.session.userId = user._id;

    return res.status(200).json({ message: 'Login successful' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

// User Logout Endpoint
app.post('/api/logout', (req, res) => {
  req.session.destroy();
  return res.status(200).json({ message: 'Logout successful' });
});

// Password Reset Request Endpoint
app.post('/api/reset-password/request', async (req, res) => {
  const { emailOrPhone } = req.body;

  try {
    // Find the user in the database by email or phone
    const user = await User.findOne().or([{ email: emailOrPhone }, { phone: emailOrPhone }]);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Generate a password reset token and expiry date
    const resetPasswordToken = generateResetPasswordToken();
    const resetPasswordTokenExpiry = generateResetPasswordTokenExpiry();

    // Update the user's reset password token and expiry date
    user.resetPasswordToken = resetPasswordToken;
    user.resetPasswordTokenExpiry = resetPasswordTokenExpiry;
    await user.save();

    // Send the password reset token to the user's email or phone number
    // ...

    return res.status(200).json({ message: 'Password reset token sent' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

// Password Reset Endpoint
app.post('/api/reset-password', async (req, res) => {
  const { resetPasswordToken, newPassword } = req.body;

  try {
    // Find the user in the database by reset password token
    const user = await User.findOne({ resetPasswordToken });

    if (!user || user.resetPasswordTokenExpiry < Date.now()) {
      return res.status(400).json({ message: 'Invalid reset password token' });
    }

    // Generate a hashed password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    // Update the user's password
    user.password = hashedPassword;
    user.resetPasswordToken = null;
    user.resetPasswordTokenExpiry = null;
    await user.save();

    return res.status(200).json({ message: 'Password reset successful' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

// Email/Phone Number Verification Endpoint
app.post('/api/verify', async (req, res) => {
  const { verificationCode } = req.body;

  try {
    // Find the user in the database by verification code
    const user = await User.findOne({ verificationCode });

    if (!user) {
      return res.status(400).json({ message: 'Invalid verification code' });
    }

    // Mark the user as verified
    user.verified = true;
    user.verificationCode = null;
    await user.save();

    return res.status(200).json({ message: 'Email/phone number verified' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

// Helper function to generate a reset password token
function generateResetPasswordToken() {
  // Generate a random string or use a library to generate a token
  // ...

  return 'reset-password-token';
}

// Helper function to generate a reset password token expiry date (1 hour from now)
function generateResetPasswordTokenExpiry() {
  const expiryDate = new Date();
  expiryDate.setHours(expiryDate.getHours() + 1);
  return expiryDate;
}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
