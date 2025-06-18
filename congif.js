const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const admin = require('firebase-admin');
const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');
const serviceAccount = require('./key.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = getFirestore();
const app = express();
const port = 3000;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.post('/signupSubmit', async (req, res) => {
  const { name, email, password } = req.body;

  const existingUser = await db.collection('SignUp-Details').where('Email', '==', email).get();
  if (!existingUser.empty) {
    return res.status(400).send('Error: Email already exists. Please use a different email.');
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  await db.collection('SignUp-Details').add({
    Name: name,
    Email: email,
    Password: hashedPassword
  });

  res.send('Sign Up successful! Please log in.');
});

app.post('/loginSubmit', async (req, res) => {
  const { email, password } = req.body;
  const userSnapshot = await db.collection('SignUp-Details').where('Email', '==', email).get();

  if (userSnapshot.empty) {
    return res.status(400).send('Error: Email not found. Please sign up.');
  }

  for (const doc of userSnapshot.docs) {
    const userData = doc.data();
    const passwordMatch = await bcrypt.compare(password, userData.Password);
    if (passwordMatch) {
      return res.redirect('/weather');
    }
  }

  return res.status(401).send('Error: Incorrect password.');
});

app.get('/weather', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'weather.html'));
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}/`);
});