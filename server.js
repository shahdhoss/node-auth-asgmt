const express = require('express');
const { hashPassword, verifyPassword } = require('./password-utils');
const { signJWT , verifyJWT} = require('./jwt-utils');

const app = express();
app.use(express.json());

const PORT = 3000;
const JWT_SECRET = 'my_secret';

const books = [
  { id: 1, title: '1984', author: 'George Orwell' },
  { id: 2, title: 'The Hobbit', author: 'J.R.R. Tolkien' },
];

const users = [];

function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'Token required' });

  try {
    // TODO: Verify JWT
    const decoded = verifyJWT(token, JWT_SECRET);
    if (!decoded) return res.status(403).json({ message: 'Invalid token' });
    req.user = decoded;
    next();
  } catch {
    res.status(403).json({ message: 'Invalid token' });
  }
}

function authorizeAdmin(req, res, next) {
  if (req.user?.role !== 'admin')
    return res.status(403).json({ message: 'Admin role required' , role: req.user.role});

  next();
}

app.post('/register', async (req, res) => {
  const { username, password, role } = req.body;

  if (!username || !password || !role)
    return res.status(400).json({ message: 'All fields required' });

  const existingUser = users.find((u) => u.username === username);

  if (existingUser)
    return res.status(409).json({ message: 'User already exists' });

  // TODO: Hash password
  const hashedPassword = hashPassword(password);
  users.push({ username, password: hashedPassword, role });

  res.status(201).json({ message: 'User registered' , user:{username, role} });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => u.username === username);

  // TODO: Verify password
  if (!user || !verifyPassword(password, user.password)) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }
  // TODO: Sign JWT
  const token = signJWT({ username , role: user.role}, JWT_SECRET, 3600)
  res.json({ token , role: user.role });
});

app.get('/books', (req, res) => {
  res.json(books);
});

app.get('/books/:id', (req, res) => {
  const book = books.find((b) => b.id === parseInt(req.params.id));

  if (!book) return res.status(404).json({ message: 'Book not found' });

  res.json(book);
});

app.post('/books', authenticate, authorizeAdmin, (req, res) => {
  const { title, author } = req.body;
  const newBook = { id: books.length + 1, title, author };

  books.push(newBook);

  res.status(201).json(newBook);
});

app.put('/books/:id', authenticate, authorizeAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const book = books.find((b) => b.id === id);

  if (!book) return res.status(404).json({ message: 'Book not found' });

  const { title, author } = req.body;

  book.title = title ?? book.title;
  book.author = author ?? book.author;

  res.json(book);
});

app.delete('/books/:id', authenticate, authorizeAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const index = books.findIndex((b) => b.id === id);

  if (index === -1) return res.status(404).json({ message: 'Book not found' });

  const deleted = books.splice(index, 1);

  res.json(deleted[0]);
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
