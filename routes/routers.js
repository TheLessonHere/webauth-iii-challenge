const router = require('express').Router();
const bcrypt = require('bcryptjs');

const db = require('./routers-model');
const restricted = require('../auth/restricted-middleware.js');
const generateToken = require('../auth/generateToken');


// users endpoint

router.get('/users', restricted, (req, res) => {
  db.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => {
      console.log(err);
      res.send(err)
    });
});

// login endpoint

router.post('/login', (req, res) => {
  let { username, password } = req.body;

  db.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        const token = generateToken(user);

        res.status(200).json({
          message: `Welcome ${user.username}!`,
          token
        });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

// register endpoint

router.post('/register', (req, res) => {
  let user = req.body;
  const hash = bcrypt.hashSync(user.password, 10); // 2 ^ n
  user.password = hash;

  db.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

module.exports = router;
