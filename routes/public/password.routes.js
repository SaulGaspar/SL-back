const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const { getDB } = require('../../config/db');
const { createTransporter } = require('../../helpers/mailer');
const { sanitizeInput, validateEmail, validatePassword } = require('../../helpers/validators');


router.post('/forgot-password', async (req, res) => {
  const { correo } = req.body;

  if (!correo || !validateEmail(correo))
    return res.status(400).json({ error: 'Email inválido' });

  const correoSafe = sanitizeInput(correo);

  try {
    const db = await getDB();
    const [users] = await db.execute('SELECT id, nombre FROM users WHERE correo = ?', [correoSafe]);

    // Respuesta genérica para no revelar si el correo existe
    if (users.length === 0)
      return res.json({ message: 'Si el correo existe, recibirás un enlace de recuperación' });

    const token   = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 3600000); // 1 hora

    await db.execute(
      'INSERT INTO Token (userId, token, expires, createdAt) VALUES (?, ?, ?, NOW())',
      [users[0].id, token, expires]
    );

    const resetLink = `${process.env.CLIENT_URL}/reset-password?token=${token}`;
    const transporter = createTransporter();

    await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: correoSafe,
      subject: 'Recuperación de contraseña - SportLike',
      html: `<p>Hola ${users[0].nombre},</p><p>Has solicitado restablecer tu contraseña. Haz clic en el siguiente enlace (válido por 1 hora):</p><a href="${resetLink}">Restablecer contraseña</a><p>Si no solicitaste esto, ignora este correo.</p>`
    });

    res.json({ message: 'Si el correo existe, recibirás un enlace de recuperación' });
  } catch (err) {
    console.error('Error en forgot-password:', err);
    res.status(500).json({ error: 'Error procesando solicitud' });
  }
});


router.post('/reset-password', async (req, res) => {
  const { token, password } = req.body;

  if (!token || !password)
    return res.status(400).json({ error: 'Token y contraseña requeridos' });

  if (!validatePassword(password))
    return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula, un número y un carácter especial' });

  try {
    const db = await getDB();
    const [rows] = await db.execute('SELECT userId, expires FROM Token WHERE token = ?', [token]);

    if (rows.length === 0)               return res.status(400).json({ error: 'Token inválido' });
    if (new Date(rows[0].expires) < new Date()) return res.status(400).json({ error: 'Token expirado' });

    const hash = await bcrypt.hash(password, 12);
    await db.execute('UPDATE users SET password = ? WHERE id = ?', [hash, rows[0].userId]);
    await db.execute('DELETE FROM Token WHERE token = ?', [token]);

    res.json({ message: 'Contraseña restablecida correctamente' });
  } catch (err) {
    console.error('Error en reset-password:', err);
    res.status(500).json({ error: 'Error restableciendo contraseña' });
  }
});

module.exports = router;
