require("dotenv").config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10
})

const app = express();
app.use(express.json());
app.use(cors());

app.use('/login', loginLimiter);


const importantKey = process.env.JWT_SECRET;
if (!importantKey) {
  console.error("JWT_SECRET is missing from .env");
  process.exit(1);
}

function authenticateToken (req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).send("Access denied.");

  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).send("Token missing.");

  jwt.verify(token, importantKey, (err, user) => {
    if (err) return res.status(401).send('Invalid token.');

    req.user = user;
    next();
  });
}

function getUsers () {
  try {
    const data = fs.readFileSync('users.json');
    return JSON.parse(data);
  }
  catch (err){
    return [];
  }
}

function saveUsers(users) {
  fs.writeFileSync("users.json", JSON.stringify(users, null, 2));
}

app.post('/register', async (req, res) => {
  const { password } = req.body;
  const users = getUsers();
  const username = req.body.username.toLowerCase();

  if (!username?.trim() || !password?.trim()) return res.status(400).send('Username and password are required.');
  if (username.includes(' ')) return res.status(400).send('Username cannot contain spaces');

  const userExists = users.find(u => u.username === username);
  if (userExists) return res.status(400).send("User already exists.");

  if (password.trim().length < 6) return res.status(400).send('Password must be at least 6 characters.')

  const hashedPassword = await bcrypt.hash(password,10);
  users.push({username, password: hashedPassword});

  saveUsers(users);
  res.send('User registered!');
});

app.post('/login', async (req, res) => {
  const { password } = req.body;
  const username = req.body.username.toLowerCase();

  const users = getUsers();
  const user = users.find(u => u.username === username);

  if (!username?.trim() || !password?.trim()) return res.status(400).send('Username and password required.')

  if (!user) return res.status(401).send('Invalid credentials.');

  const valid = await bcrypt.compare(password, user.password)
  if (!valid) return res.status(401).send('Invalid credentials.');

  const token = jwt.sign(
    {username },
    importantKey,
    { expiresIn: '1h' }
  );

  res.json({ token });
});

app.get('/dashboard', authenticateToken, (req,res) => {
  res.send(`Welcome ${req.user.username}`);
});

app.listen(3000,() => {
  console.log('Server running on port 3000');
})