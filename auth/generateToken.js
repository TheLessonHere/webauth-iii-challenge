const jwt = require('jsonwebtoken');
const secrets = require('../config/secrets');

module.exports = function generateToken(user){
    const payload = {
      subject: user.id, //sub
      username: user.username
    };
    const options = {
      expiresIn: '1d'
    };
    return jwt.sign(payload, secrets.jwtSecret, options)
  }