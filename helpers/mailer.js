const nodemailer = require('nodemailer');

// ================================
// 📧 MAILER - TRANSPORTER
// ================================

function createTransporter() {
  const port = Number(process.env.EMAIL_PORT) || 587;
  return nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port,
    secure: port === 465,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });
}

module.exports = { createTransporter };
