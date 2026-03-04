const nodemailer = require('nodemailer');

// ================================
// 📧 MAILER - TRANSPORTER
// ================================

function createTransporter() {
  return nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: false,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });
}

module.exports = { createTransporter };
