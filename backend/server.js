import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const app = express();


app.use(express.json());
app.use(cookieParser());
app.use(cors({ credentials: true, origin: 'http://localhost:5173' }));


const SECRET_KEY = 'your-secret-key'; // Replace with a strong secret key
const ACCESS_TOKEN_EXPIRY = '15m'; // Short-lived access token
const REFRESH_TOKEN_EXPIRY = '7d'; // Long-lived refresh token


const users = [];

const generateTokens = (userId) => {
  const accessToken = jwt.sign({ userId }, SECRET_KEY, { expiresIn: ACCESS_TOKEN_EXPIRY });
  const refreshToken = jwt.sign({ userId }, SECRET_KEY, { expiresIn: REFRESH_TOKEN_EXPIRY });
  return { accessToken, refreshToken };
};


app.post('/api/User/sign_up', async (req, res) => {
  const { firstName, lastName, email, contact, password } = req.body;

  try {
    const userExists = users.some((user) => user.email === email);
    if (userExists) {
      return res.status(400).json({ message: 'User already exists' });
    }


    const hashedPassword = await bcrypt.hash(password, 10);

    
    const newUser = {
      id: users.length + 1,
      firstName,
      lastName,
      email,
      contact,
      password: hashedPassword,
    };
    users.push(newUser);

    
    const { accessToken, refreshToken } = generateTokens(newUser.id);

    
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: true, // Enable in production (HTTPS)
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    
    res.status(201).json({ message: 'Signup successful!', accessToken });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


app.post('/api/User/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = users.find((user) => user.email === email);
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

  
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    
    const { accessToken, refreshToken } = generateTokens(user.id);

    
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: true, 
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

  
    res.json({ message: 'Login successful!', accessToken });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


app.post('/api/User/refresh', (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) {
    return res.status(401).json({ message: 'No refresh token provided' });
  }

 
  jwt.verify(refreshToken, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid refresh token' });
    }

    
    const accessToken = jwt.sign({ userId: decoded.userId }, SECRET_KEY, {
      expiresIn: ACCESS_TOKEN_EXPIRY,
    });
    res.json({ accessToken });
  });
});


app.post('/api/User/logout', (req, res) => {
  res.clearCookie('refreshToken');
  res.json({ message: 'Logged out successfully' });
});


const PORT = 5000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});