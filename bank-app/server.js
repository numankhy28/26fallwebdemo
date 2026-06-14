const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const PORT = 3000;

// Middleware
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Allow requests from Attacker Site for specific endpoints
app.use(cors({
  origin: 'http://localhost:4000',
  credentials: true
}));

// Session configuration
app.use(session({
  name: 'session_id', // Name of the cookie
  secret: 'super-secret-key-123',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true, // Set to true for secure sessions
    secure: false, // Intentionally false for localhost demo
    sameSite: 'lax', // Default behavior
    maxAge: 1000 * 60 * 60 * 24 // 1 day
  }
}));

// In-memory database
const users = {
  'user': {
    password: 'password',
    balance: 30000
  }
};

// Custom middleware to require login
function requireLogin(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  res.redirect('/login');
}

// Generate CSRF Token Middleware
function generateCsrfToken(req, res, next) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = uuidv4();
  }
  res.locals.csrfToken = req.session.csrfToken;
  next();
}

// --- Routes ---

app.get('/', (req, res) => {
  if (req.session.userId) {
    res.redirect('/dashboard');
  } else {
    res.redirect('/login');
  }
});

app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (users[username] && users[username].password === password) {
    req.session.userId = username;
    // Set a strict cookie for SameSite demo
    res.cookie('session_id_strict', 'strict-value-123', {
      httpOnly: true,
      secure: false,
      sameSite: 'strict',
      maxAge: 1000 * 60 * 60 * 24
    });
    res.redirect('/dashboard');
  } else {
    res.render('login', { error: 'Invalid username or password' });
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.clearCookie('session_id_strict');
  res.redirect('/login');
});

app.get('/dashboard', requireLogin, generateCsrfToken, (req, res) => {
  const user = users[req.session.userId];
  res.render('dashboard', {
    user: req.session.userId,
    balance: user.balance
  });
});

// Helper function to process transfer
function processTransfer(req, res, amount, to, method) {
  const numAmount = parseInt(amount, 10);
  if (isNaN(numAmount) || numAmount <= 0) {
    return res.render('result', { success: false, message: 'Invalid amount.' });
  }

  const user = users[req.session.userId];
  if (user.balance < numAmount) {
    return res.render('result', { success: false, message: 'Insufficient funds.' });
  }

  user.balance -= numAmount;
  res.render('result', {
    success: true,
    message: `Successfully transferred $${numAmount} to ${to} via ${method}.`
  });
}

// 1. VULNERABLE ENDPOINTS

// GET-based CSRF Vulnerability
app.get('/transfer-get', requireLogin, (req, res) => {
  const { amount, to } = req.query;
  processTransfer(req, res, amount, to, 'Vulnerable GET Method');
});

// POST-based CSRF Vulnerability
app.post('/transfer-vulnerable', requireLogin, (req, res) => {
  const { amount, to } = req.body;
  processTransfer(req, res, amount, to, 'Vulnerable POST Method');
});

// 2. PROTECTED ENDPOINTS

// Protection 1: Anti-CSRF Token
app.post('/transfer-token', requireLogin, (req, res) => {
  const { amount, to, _csrf } = req.body;
  if (!_csrf || _csrf !== req.session.csrfToken) {
    return res.status(403).render('result', {
      success: false,
      message: 'CSRF Attack Blocked! Invalid or Missing Anti-CSRF Token.'
    });
  }
  processTransfer(req, res, amount, to, 'Anti-CSRF Token Protected POST');
});

// Protection 2: Custom Header (e.g., X-Requested-With)
app.post('/transfer-header', requireLogin, (req, res) => {
  const { amount, to } = req.body;
  const customHeader = req.headers['x-requested-with'];

  if (customHeader !== 'XMLHttpRequest') {
    return res.status(403).render('result', {
      success: false,
      message: 'CSRF Attack Blocked! Missing or Invalid Custom Header (X-Requested-With).'
    });
  }
  processTransfer(req, res, amount, to, 'Custom Header Protected POST');
});

// Protection 3: Fetch Metadata
app.post('/transfer-metadata', requireLogin, (req, res) => {
  const { amount, to } = req.body;
  const fetchSite = req.headers['sec-fetch-site'];

  // Accept only same-origin or none (direct navigation). 
  // same-site is rejected because different ports on localhost are considered same-site!
  if (fetchSite !== 'same-origin' && fetchSite !== 'none') {
    return res.status(403).render('result', {
      success: false,
      message: 'CSRF Attack Blocked! Sec-Fetch-Site indicates a cross-site or cross-port request.'
    });
  }
  processTransfer(req, res, amount, to, 'Fetch Metadata Protected POST');
});

// Protection 4: SameSite Cookies
app.post('/transfer-samesite', requireLogin, (req, res) => {
  const { amount, to } = req.body;

  // Check for the strict cookie
  const strictCookie = req.cookies['session_id_strict'];

  if (!strictCookie || strictCookie !== 'strict-value-123') {
    return res.status(403).render('result', {
      success: false,
      message: 'CSRF Attack Blocked! SameSite=Strict cookie is missing.'
    });
  }
  processTransfer(req, res, amount, to, 'SameSite Protected POST');
});

app.listen(PORT, () => {
  console.log(`Bank App listening on http://localhost:${PORT}`);
});
