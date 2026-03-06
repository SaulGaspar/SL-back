const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');

const { getDB } = require('../../config/db');
const { authMiddleware, adminOnly } = require('../../middlewares/auth');
const { createTransporter } = require('../../helpers/mailer');
const { sanitizeInput, validateUsername, generarPasswordAleatoria } = require('../../helpers/validators');

// GET /api/admin/users/stats/summary
router.get('/stats/summary', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();

    const [stats] = await db.execute(`
      SELECT 
        COUNT(*) AS total_usuarios,
        SUM(CASE WHEN rol = 'admin'   THEN 1 ELSE 0 END) AS admins,
        SUM(CASE WHEN rol = 'cliente' THEN 1 ELSE 0 END) AS clientes,
        SUM(CASE WHEN verificado = 1  THEN 1 ELSE 0 END) AS verificados,
        SUM(CASE WHEN verificado = 0  THEN 1 ELSE 0 END) AS sin_verificar,
        SUM(CASE WHEN lockedUntil IS NOT NULL AND lockedUntil > NOW() THEN 1 ELSE 0 END) AS bloqueados
      FROM users
    `);

    const [registrosPorMes] = await db.execute(`
      SELECT DATE_FORMAT(createdAt, '%Y-%m') AS mes, COUNT(*) AS registros
      FROM users
      WHERE createdAt >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
      GROUP BY mes ORDER BY mes
    `);

    res.json({ resumen: stats[0], registrosPorMes });
  } catch (err) {
    console.error('Error obteniendo estadísticas de usuarios:', err);
    res.status(500).json({ error: 'Error obteniendo estadísticas' });
  }
});

// GET /api/admin/users
router.get('/', authMiddleware, adminOnly, async (req, res) => {
  const { rol, verificado, search } = req.query;

  try {
    const db = await getDB();

    let sql = `
      SELECT id, nombre, apellidoP, apellidoM, correo, telefono,
             usuario, rol, verificado, failedAttempts, lockedUntil, createdAt, updatedAt
      FROM users WHERE 1=1
    `;

    const params = [];

    if (rol && rol !== 'all') { sql += ' AND rol = ?'; params.push(rol); }
    if (verificado !== undefined && verificado !== 'all') { sql += ' AND verificado = ?'; params.push(verificado); }
    if (search) {
      sql += ' AND (nombre LIKE ? OR apellidoP LIKE ? OR usuario LIKE ? OR correo LIKE ?)';
      const s = `%${search}%`;
      params.push(s, s, s, s);
    }

    sql += ' ORDER BY createdAt DESC';

    const [rows] = await db.execute(sql, params);
    res.json(rows);
  } catch (err) {
    console.error('Error obteniendo usuarios:', err);
    res.status(500).json({ error: 'Error al obtener usuarios' });
  }
});

// GET /api/admin/users/:id
router.get('/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT id, nombre, apellidoP, apellidoM, fechaNac, correo, telefono, usuario, rol,
             verificado, failedAttempts, lockedUntil, createdAt, updatedAt
      FROM users WHERE id = ?
    `, [req.params.id]);

    if (rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

    const [orders] = await db.execute(`
      SELECT id, total, fecha, status, sucursal FROM orders WHERE user_id = ? ORDER BY fecha DESC LIMIT 10
    `, [req.params.id]);

    res.json({ user: rows[0], orders });
  } catch (err) {
    console.error('Error obteniendo usuario:', err);
    res.status(500).json({ error: 'Error al obtener usuario' });
  }
});

// PUT /api/admin/users/:id
router.put('/:id', authMiddleware, adminOnly, async (req, res) => {
  const { nombre, apellidoP, apellidoM, telefono, usuario, rol, verificado } = req.body;

  if (!nombre || !apellidoP || !usuario)  return res.status(400).json({ error: 'Faltan campos requeridos' });
  if (!validateUsername(usuario))          return res.status(400).json({ error: 'Usuario inválido' });
  if (rol && !['admin', 'cliente'].includes(rol)) return res.status(400).json({ error: 'Rol inválido' });

  const nombreSafe    = sanitizeInput(nombre);
  const apellidoPSafe = sanitizeInput(apellidoP);
  const apellidoMSafe = apellidoM ? sanitizeInput(apellidoM) : null;
  const usuarioSafe   = sanitizeInput(usuario);
  const telefonoSafe  = telefono ? sanitizeInput(telefono) : null;

  try {
    const db = await getDB();

    const [exists] = await db.execute('SELECT id FROM users WHERE id = ?', [req.params.id]);
    if (exists.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

    const [duplicates] = await db.execute(
      'SELECT id FROM users WHERE (usuario = ? OR telefono = ?) AND id != ?',
      [usuarioSafe, telefonoSafe, req.params.id]
    );
    if (duplicates.length > 0) return res.status(400).json({ error: 'Usuario o teléfono ya registrado' });

    await db.execute(`
      UPDATE users SET nombre=?, apellidoP=?, apellidoM=?, telefono=?, usuario=?, rol=?, verificado=?, updatedAt=NOW()
      WHERE id=?
    `, [nombreSafe, apellidoPSafe, apellidoMSafe, telefonoSafe, usuarioSafe, rol || 'cliente', verificado !== undefined ? verificado : 1, req.params.id]);

    console.log(`✅ Usuario actualizado: ${usuarioSafe} (ID: ${req.params.id}) por admin ${req.user.usuario}`);
    res.json({ message: 'Usuario actualizado correctamente' });
  } catch (err) {
    console.error('Error actualizando usuario:', err);
    res.status(500).json({ error: 'Error actualizando usuario' });
  }
});

// DELETE /api/admin/users/:id
router.delete('/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();

    if (req.user.id === parseInt(req.params.id)) {
      return res.status(400).json({ error: 'No puedes eliminar tu propia cuenta' });
    }

    const [exists] = await db.execute('SELECT id, usuario FROM users WHERE id = ?', [req.params.id]);
    if (exists.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

    await db.execute('UPDATE users SET verificado = 0, updatedAt = NOW() WHERE id = ?', [req.params.id]);

    console.log(`⚠️ Usuario desactivado: ${exists[0].usuario} (ID: ${req.params.id}) por admin ${req.user.usuario}`);
    res.json({ message: 'Usuario desactivado correctamente' });
  } catch (err) {
    console.error('Error eliminando usuario:', err);
    res.status(500).json({ error: 'Error eliminando usuario' });
  }
});

// PATCH /api/admin/users/:id/unlock
router.patch('/:id/unlock', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const [exists] = await db.execute('SELECT id, usuario FROM users WHERE id = ?', [req.params.id]);
    if (exists.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

    await db.execute('UPDATE users SET failedAttempts = 0, lockedUntil = NULL, updatedAt = NOW() WHERE id = ?', [req.params.id]);

    console.log(`🔓 Usuario desbloqueado: ${exists[0].usuario} por admin ${req.user.usuario}`);
    res.json({ message: 'Usuario desbloqueado correctamente' });
  } catch (err) {
    console.error('Error desbloqueando usuario:', err);
    res.status(500).json({ error: 'Error desbloqueando usuario' });
  }
});

// POST /api/admin/users/:id/reset-password
router.post('/:id/reset-password', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const [user] = await db.execute('SELECT id, usuario, correo, nombre FROM users WHERE id = ?', [req.params.id]);
    if (user.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

    const tempPassword = generarPasswordAleatoria(12);
    const hash = await bcrypt.hash(tempPassword, 12);

    await db.execute('UPDATE users SET password = ?, updatedAt = NOW() WHERE id = ?', [hash, req.params.id]);

    const transporter = createTransporter();
    await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: user[0].correo,
      subject: 'Contraseña restablecida - SportLike',
      html: `<p>Hola ${user[0].nombre},</p><p>Tu contraseña ha sido restablecida por un administrador.</p><p><strong>Tu nueva contraseña temporal es:</strong> ${tempPassword}</p><p>Por seguridad, te recomendamos cambiarla al iniciar sesión.</p>`
    });

    console.log(`🔑 Contraseña reseteada para: ${user[0].usuario} por admin ${req.user.usuario}`);
    res.json({ message: 'Contraseña restablecida. Se ha enviado la nueva contraseña al correo del usuario.', tempPassword });
  } catch (err) {
    console.error('Error reseteando contraseña:', err);
    res.status(500).json({ error: 'Error reseteando contraseña' });
  }
});

module.exports = router;