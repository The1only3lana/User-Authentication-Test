// Test User Authentication - Elaina 
// This is NOT perfect and NOT secure enough, needs HTTPS and further security measures.
// Need to implement short-lived tokens + refresh tokens.

/* DOWNLOAD THE FOLLOWING DEPENDENCIES IN THE TERMINAL
    "bcryptjs": "^3.0.3",
    "cookie-parser": "^1.4.7",
    "dotenv": "^17.3.1",
    "express": "^5.2.1",
    "express-rate-limit": "^8.3.1",
    "helmet": "^8.1.0",
    "jsonwebtoken": "^9.0.3"
*/

// Needed to grab the dotenv file where secret key is found
// Store it in .env for security reasons
// Make sure .env is included in .gitignore, makes it invisible on the github page.
require("dotenv").config();

// What we use to run the server.
const express = require('express');

// Creates & verifies login tokens.
const jwt = require('jsonwebtoken');

// Used to hash passwords securely.
const bcrypt = require('bcryptjs');

// Used to read users.json and write in it.
const fs = require('fs');

// Used for safe file paths.
const path = require('path');

// Adds necessary security headers to help prevent XSS attacks and more.
const helmet = require('helmet');

// Used to block spam login attempts and registers.
const rateLimit = require('express-rate-limit');

//Allows us to read cookies (req.cookies).
const cookieParser = require('cookie-parser');

// Limites how many attempts can be done (10), and how much time you have.
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 Minutes
  max: 10, // 10 Attempts
  handler: (req, res) => {
    res.status(429).json({ error: 'Too many login attempts. Try later. '})
  }
})

// This Creates your server   RRR
const app = express();

// Middleware Setup: 
// Middleware = code that runs before routes
app.use(express.json()); //Allows reading: Without it → body would be empty. RRR
app.use(cookieParser()); //
app.use(helmet()); //Adds security headers.

// Sets as the default page
app.get('/', (req,res)=>{
  res.sendFile(__dirname + '/public/register.html');
});

// Sets the attempt limiters.   
// This Limits requests to: /register & /login. Not to other routes.
app.use('/register', limiter);
app.use('/login', limiter);

// Secret Key Check: Stops server if secret key missing.
// Good security practice.
const importantKey = process.env.JWT_SECRET;
if (!importantKey) {
  console.error("JWT_SECRET is missing from .env");
  process.exit(1);
}

// Token Authentication Function: This protects private routes. 
function authenticateToken (req, res, next) {
  const token = req.cookies.token; //1) Get Token: Reads cookie

  if (!token) return res.redirect('/login.html'); //2) If No Token: (Not logged in → redirect)

  jwt.verify(token, importantKey, (err, user) => { //Verify Token 3) Checks if token: Is valid & Was created by your server
    if (err) return res.redirect('/login.html'); //4) If Invalid: Reject user.

    req.user = user;
    next(); //5)If Valid: Stores user info and continues.
  })
}

// User Storage Functions
// Get Users
function getUsers () {
  try {
    const data = fs.readFileSync('users.json'); //Reads: users.json
    return JSON.parse(data); //Returns array: JSON = [ {"username":"john", "password":"hashedpass"}]   RRR
  }
  catch (err){ // If file is missing: Returns an empty array.
    return [];
  }
}

// Save Users
function saveUsers(users) {
  fs.writeFileSync("users.json", JSON.stringify(users, null, 2)); //Sets the users in the JSON file.
}  

// Upon receiving a post request from register, run the following ->
app.post('/register', async (req, res) => {  // Runs when user submits the Register form.

  // Get Data
  const { password } = req.body;

  //Lowercase usernames: To Prevents duplicates. EX: John → john
  const users = getUsers();
  const username = req.body.username.toLowerCase();

  // Validate Input: Rejects empty fields. / requires Username and password   RRR
  if (!username?.trim() || !password?.trim()) return res.status(400).send('Username and password are required.');
  // No spaces allowed: This Prevent Spaces in the Username
  if (username.includes(' ')) return res.status(400).send('Username cannot contain spaces');

  // Check for Existing Users
  const userExists = users.find(u => u.username === username);  // Check for if the User Exists  
  //If found: send/say "User already exists"
  if (userExists) return res.status(400).send("User already exists.");

  //Password Length Check
  if (password.trim().length < 6) return res.status(400).send('Password must be at least 6 characters.')  //Checks the length of the Password, to make sure that its a minimum of 6 characters
  //Minimum of 6 characters
  
  //10 = salt rounds (security level).  This makes the password hard to crack while keeping your app fast.
  const hashedPassword = await bcrypt.hash(password,10);  //In bcrypt, the number 10 (often called saltRounds) represents the cost factor, which determines the computational effort required to hash the password.
  //Here it tells the algorithm to run 1,024 iterations. RRR

  //Save User
  users.push({username, password: hashedPassword}); 


  saveUsers(users);    // Adds/pushes User to file.
  res.send('User registered!');   //Send Response
});


//Login Route
app.post('/login', async (req, res) => {     //Runs when logging in.
  const { password } = req.body;
  const username = req.body.username.toLowerCase();

  //Find User
  const users = getUsers();
  const user = users.find(u => u.username === username);  //Find User


  if (!username?.trim() || !password?.trim()) return res.status(400).send('Username and password required.')  // If found:

  if (!user) return res.status(401).send('Invalid credentials.');  // If not found:

  //Check Password
  const valid = await bcrypt.compare(password, user.password)  //Compares: typed password vs hashed password
  if (!valid) return res.status(401).send('Invalid credentials.');

  //Create Token
  const token = jwt.sign(  //Token contains: JSON = { "username":"john" }   RRR
    {username },
    importantKey,    //Signed using: JWT_SECRET    RRR
    { expiresIn: '1h' }  //This Token will Expire in: 1 hour
  );

  //Store Token in Cookie    RRR
  res.cookie('token', token, {   //Saves token in browser cookie.
    //Cookie Settings
    httpOnly: true,   //JavaScript cannot read cookie. //(Protects against XSS.)   RRR   RRR   RRR
    secure: process.env.NODE_ENV === 'production', // Only over HTTPS     //Meaning: HTTPS only in production | This is a Very good practice  RRR
    sameSite: 'Strict',   //Prevents: Cross-site attacks
    maxAge: 60 * 60 * 1000 //Expires in: 1 Hour
  });

  res.send('Logged in!');
});

//Logout Route
app.post('/logout', (req,res)=>{   //Clears cookie:
  res.clearCookie('token', {   //User logged out.
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', // Only over HTTPS
    sameSite: 'Strict',
    path: '/'
  });

  res.sendStatus(200);
});

//Protected Dashboard
app.get(['/dashboard','/dashboard/'], authenticateToken, (req,res) => {   //This route requires (login): "authenticateToken" Runs first: So No token → redirect Valid token → allow access  RRR
  //Send Dashboard
  res.sendFile(path.join(__dirname,'private','dashboard.html')); //Only logged-in users see this page.
});

//API User Route
app.get('/api/user', authenticateToken, (req, res) => {  //Useful for: 1)Showing username. 2)Personalizing UI
  res.json({ username: req.user.username });
});

//Serve static files from the 'public' directory, lets us not have to trype in the FULL directory for files in the public folder.
app.use(express.static(path.join(__dirname, 'frontend/public')));

///Start Server
app.listen(3000,() => {  //Server runs at: http://localhost:3000
  console.log('Server running on port 3000');
  //Error Handling
}).on("error", (err) => {  //If server fails → logs error.
  console.error("Server failed to start:", err);
});
