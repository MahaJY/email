const jwt = require('jsonwebtoken');
const UserAuth = require('../models/empmodel'); 
const jwtutils = require('../utils/JWTutils');
const bcrypt = require('bcrypt');
const handlebars = require('handlebars');
const nodemailer = require('nodemailer');
require('dotenv').config(); 
const fs = require('fs');


const register = async(req,res)=>{
    const { name,age,email,username, password,role } = req.body;

    try {
      const newUser = await UserAuth.create({ name,age,email,username, password,role });
      const templateFile = fs.readFileSync('./assets/email.html', 'utf-8');
      const template = handlebars.compile(templateFile);
      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.GMAIL_EMAIL,
            pass: process.env.GMAIL_PASSWORD
        }
    });

    const mailOptions = {
        from: process.env.GMAIL_EMAIL,
        to: email, 
        subject: 'Registration Confirmation',
        html: template({name})
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error('Error sending email:', error);
        } else {
            console.log('Email sent:', info.response);
        }
    });
      
    res.status(201).json({ id: newUser.id, username });
    } catch (error) {
      console.error(error);
      res.status(500).send('Error registering user');
    }
  };
  const authenticateUser = async (username, password, role) => {
    try {
      const user = await UserAuth.findOne({
        where: {
          username,
          role,
        },
      });
  
      if (user && bcrypt.compareSync(password, user.password)) {
        const accessToken = jwtutils.generateaccessToken(user);
        const refreshToken = jwtutils.generateRefreshToken();
        jwtutils.refreshTokens[refreshToken] = user;
  
        return { access_token: accessToken, refresh_token: refreshToken };
      } else {
        throw new Error('Invalid credentials');
      }
    } catch (error) {
      console.error(error);
      throw new Error('Error during login');
    }
  };
  
  const login = async (req, res) => {
    const { username, password, role } = req.body;
  
    try {
      const tokens = await authenticateUser(username, password, role);
      res.json(tokens);
    } catch (error) {
      console.error(error);
      res.status(500).send('Error during login');
    }
  };
const refreshToken = (req, res) => {
  const refreshToken = req.body.refresh_token;
  if (!refreshToken || !jwtutils.refreshTokens[refreshToken]) {
    return res.status(403).json({ error: 'Invalid refresh token' });
  }
const userData = jwtutils.refreshTokens[refreshToken];
  const accessToken = jwtutils.generateaccessToken(userData);
  res.json({ access_token: accessToken });
};
module.exports = {
    register,
    login,
  refreshToken,
};