const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();

app.use(express.json());

const file = path.join(__dirname, 'data/products.json');

const PASSWORD = process.env.ADMIN_PASSWORD || 'CHANGE-ME-1234';
const sessions = new Set();

const read = () => JSON.parse(fs.readFileSync(file));
const write = x => fs.writeFileSync(file, JSON.stringify(x, null, 2));

function auth(req, res, next) {
  let t = (req.headers.authorization || '').replace('Bearer ', '');

  if (!sessions.has(t)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  next();
}

app.post('/api/login', (req, res) => {
  if (req.body.password !== PASSWORD) {
    return res.status(401).json({ error: 'Wrong password' });
  }

  let t = crypto.randomBytes(24).toString('hex');
  sessions.add(t);

  res.json({ token: t });
});

app.get('/api/products', (req, res) => {
  res.json(read());
});

app.post('/api/products', auth, (req, res) => {
  let a = read();
  let x = { id: Date.now(), ...req.body };

  a.push(x);
  write(a);

  res.json(x);
});

app.put('/api/products/:id', auth, (req, res) => {
  let a = read();
  let i = a.findIndex(x => String(x.id) === req.params.id);

  if (i < 0) {
    return res.sendStatus(404);
  }

  a[i] = { ...a[i], ...req.body, id: a[i].id };
  write(a);

  res.json(a[i]);
});

app.delete('/api/products/:id', auth, (req, res) => {
  write(read().filter(x => String(x.id) !== req.params.id));
  res.sendStatus(204);
});

app.use(express.static(path.join(__dirname, 'public')));

module.exports = app;
