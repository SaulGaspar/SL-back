const express = require('express');
const router = express.Router();

const { getDB } = require('../../config/db');

router.post('/', async (req, res) => {
  const name = String(req.body?.nombre || '').trim();
  const email = String(req.body?.email || '').trim().toLowerCase();
  const message = String(req.body?.mensaje || '').trim();

  if (name.length < 2 || name.length > 120) {
    return res.status(400).json({ error: 'Escribe un nombre válido.' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 150) {
    return res.status(400).json({ error: 'Escribe un correo válido.' });
  }
  if (message.length < 10 || message.length > 2000) {
    return res.status(400).json({ error: 'El mensaje debe tener entre 10 y 2000 caracteres.' });
  }

  try {
    const db = await getDB();
    const [result] = await db.execute(
      `INSERT INTO mensajes_contacto (nombre, correo, mensaje)
       VALUES (?, ?, ?)`,
      [name, email, message]
    );
    res.status(201).json({ id: result.insertId, message: 'Mensaje recibido correctamente.' });
  } catch (error) {
    console.error('Error guardando mensaje de contacto:', error.message);
    res.status(500).json({ error: 'No se pudo enviar el mensaje. Intenta más tarde.' });
  }
});

module.exports = router;
