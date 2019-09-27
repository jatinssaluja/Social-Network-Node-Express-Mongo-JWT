const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const {
  check,
  validationResult
} = require('express-validator/check');
const auth = require('../../middleware/auth');
const User = require('../../models/User');

// @route GET api/auth
// @access public
router.get('/', auth, async (req, res) => {


  try {

    const user = await User.findById(req.user.id).select('-password');
    res.json(user);

  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server Error");

  }
});

// @route POST api/auth
// @desc  Authenticate User and Get token
// @access public
router.post('/', [
  check('email', 'Insert Valid Email').isEmail(),
  check('password', 'Password is required').exists()
], async (req, res) => {

  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    // Bad Request
    return res.status(400).json({
      errors: errors.array()
    });
  }

  const {
    email,
    password
  } = req.body;
  try {

    // See if User Exists

    let user = await User.findOne({
      email
    });

    if (!user) {
      return res.status(400).json({
        errors: [{
          msg: "Invalid Email or Password"
        }]
      });
    }

    // Check if Password is valid
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({
        errors: [{
          msg: "Invalid Email or Password"
        }]
      });
    }



    // Return Json Web Token

    const payload = {
      user: {
        id: user.id
      }
    };

    jwt.sign(payload, config.get('jwtSecret'), {
        expiresIn: 36000
      },
      (err, token) => {

        if (err) throw err;
        res.json({
          token
        });

      });

    //res.send('User Registered');

  } catch (err) {

    console.error(err.message);
    res.status(500).send("Server Error");

  }

});

module.exports = router;