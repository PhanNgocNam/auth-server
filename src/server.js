const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// In-memory users store
const users = [
  { id: 1, username: 'admin', password: 'password', role: 'admin' },
  { id: 2, username: 'user', password: 'password', role: 'user' }
];

const JWT_SECRET = 'secret';

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
}

function authorizeRoles(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Forbidden' });
    }
    next();
  };
}

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.password === password);
  if (!user) return res.status(401).json({ message: 'Invalid credentials' });

  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

app.get('/profile', authenticateToken, (req, res) => {
  res.json({ id: req.user.id, username: req.user.username, role: req.user.role });
});

app.get('/admin', authenticateToken, authorizeRoles('admin'), (req, res) => {
  res.json({ message: 'Welcome Admin!' });
});

const port = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(port, () => console.log(`Server running on port ${port}`));
}

module.exports = { app, users };
