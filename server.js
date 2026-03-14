require("dotenv").config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  handler: (req, res) => {
    res.status(429).json({ error: 'Too many login attempts. Try later. '})
  }
})

const app = express();

app.use(express.json());
app.use(cookieParser());
app.use(helmet());

// Sets as the default page
app.get('/', (req,res)=>{
  res.sendFile(__dirname + '/public/register.html');
});

app.get('/test', (req,res)=>{
  res.send("Server works");
});


app.use('/register', limiter);
app.use('/login', limiter);

const importantKey = process.env.JWT_SECRET;
if (!importantKey) {
  console.error("JWT_SECRET is missing from .env");
  process.exit(1);
}

function authenticateToken (req, res, next) {
  const token = req.cookies.token; 
  console.log("Token:", token);

  if (!token) return res.redirect('/login.html');

  jwt.verify(token, importantKey, (err, user) => {
    if (err) return res.redirect('/login.html');

    req.user = user;
    next();
  })
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

  res.cookie('token', token, {
    httpOnly: true,
    secure: false,
    sameSite: 'Strict',
    maxAge: 60 * 60 * 1000
  });

  res.send('Logged in!');
});

app.post('/logout', (req,res)=>{
console.log("Cookies before clearing:", req.cookies);
  res.clearCookie('token', {
    httpOnly: true,
    secure: false,
    sameSite: 'Strict',
    path: '/'
  });

  res.sendStatus(200);
});

app.get(['/dashboard','/dashboard/'], authenticateToken, (req,res) => {
  console.log(req);
  res.sendFile(path.join(__dirname,'private','dashboard.html'));
});

app.use((req, res, next) => {
  console.log('Incoming request:', req.method, req.url);
  next();
});

app.use(express.static('public'));

app.listen(3000,() => {
  console.log('Server running on port 3000');
}).on("error", (err) => {
  console.error("Server failed to start:", err);
});
