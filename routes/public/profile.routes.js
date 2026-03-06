const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');

const { getDB } = require('../../config/db');
const { authMiddleware } = require('../../middlewares/auth');
const { sanitizeInput, validatePassword, validateUsername } = require('../../helpers/validators');


router.get('/me', authMiddleware, async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(
      'SELECT id, nombre, apellidoP, apellidoM, usuario, correo, rol FROM users WHERE id = ?',
      [req.user.id]
    );

    if (rows.length === 0) return res.status(404).json({ error: 'Usuario no existe' });

    res.json(rows[0]);
  } catch (err) {
    console.error('Error obteniendo usuario:', err);
    res.status(500).json({ error: 'Error obteniendo usuario' });
  }
});


router.post('/update-profile', authMiddleware, async (req, res) => {
  const { nombre, apellidoP, apellidoM, telefono, usuario } = req.body;

  if (!nombre || !apellidoP || !usuario)
    return res.status(400).json({ error: 'Faltan campos requeridos' });

  if (!validateUsername(usuario))
    return res.status(400).json({ error: 'Usuario inválido' });

  const nombreSafe    = sanitizeInput(nombre);
  const apellidoPSafe = sanitizeInput(apellidoP);
  const apellidoMSafe = apellidoM ? sanitizeInput(apellidoM) : null;
  const usuarioSafe   = sanitizeInput(usuario);
  const telefonoSafe  = telefono ? sanitizeInput(telefono) : null;

  try {
    const db = await getDB();

    const [exists] = await db.execute(
      'SELECT id FROM users WHERE (usuario = ? OR telefono = ?) AND id != ?',
      [usuarioSafe, telefonoSafe, req.user.id]
    );
    if (exists.length > 0)
      return res.status(400).json({ error: 'Usuario o teléfono ya registrado' });

    await db.execute(
      'UPDATE users SET nombre=?, apellidoP=?, apellidoM=?, telefono=?, usuario=?, updatedAt=NOW() WHERE id=?',
      [nombreSafe, apellidoPSafe, apellidoMSafe, telefonoSafe, usuarioSafe, req.user.id]
    );

    res.json({ message: 'Perfil actualizado correctamente' });
  } catch (err) {
    console.error('Error actualizando perfil:', err);
    res.status(500).json({ error: 'Error actualizando perfil' });
  }
});


router.post('/update-password', authMiddleware, async (req, res) => {
  const { actual, nueva } = req.body;

  if (!actual || !nueva)
    return res.status(400).json({ error: 'Debes enviar ambas contraseñas' });

  if (!validatePassword(nueva))
    return res.status(400).json({ error: 'La nueva contraseña no cumple los requisitos de seguridad' });

  try {
    const db = await getDB();
    const [rows] = await db.execute('SELECT password FROM users WHERE id=?', [req.user.id]);

    if (rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

    const match = await bcrypt.compare(actual, rows[0].password);
    if (!match) return res.status(401).json({ error: 'La contraseña actual es incorrecta' });

    const hash = await bcrypt.hash(nueva, 12);
    await db.execute('UPDATE users SET password=?, updatedAt=NOW() WHERE id=?', [hash, req.user.id]);

    res.json({ message: 'Contraseña actualizada correctamente' });
  } catch (err) {
    console.error('Error actualizando contraseña:', err);
    res.status(500).json({ error: 'Error actualizando contraseña' });
  }
});

module.exports = router;
