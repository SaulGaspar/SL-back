// ============================================================
// routes/user/addresses.js
// Endpoints REST para gestión de direcciones de envío
//
// Monta en tu app así (en server.js / app.js):
//   const addressesRouter = require('./routes/user/addresses');
//   app.use('/api/user/addresses', addressesRouter);
//
// Requiere: authMiddleware que ponga req.user.id
// ============================================================

const express = require('express');
const router  = express.Router();
const { getDB }          = require('../../config/db');
const { authMiddleware } = require('../../middlewares/auth');

// ── Límite de direcciones por usuario ──
const MAX_ADDRESSES = 10;

// ============================================================
// GET /api/user/addresses
// Devuelve todas las direcciones del usuario autenticado
// ============================================================
router.get('/', authMiddleware, async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(
      `SELECT * FROM user_addresses
       WHERE user_id = ? AND activo = 1
       ORDER BY predeterminada DESC, created_at DESC`,
      [req.user.id]
    );
    res.json(rows);
  } catch (err) {
    console.error('Error obteniendo direcciones:', err);
    res.status(500).json({ error: 'Error obteniendo direcciones' });
  }
});

// ============================================================
// GET /api/user/addresses/:id
// Obtiene una dirección específica (debe pertenecer al usuario)
// ============================================================
router.get('/:id', authMiddleware, async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(
      `SELECT * FROM user_addresses
       WHERE id = ? AND user_id = ? AND activo = 1`,
      [req.params.id, req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Dirección no encontrada' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Error obteniendo dirección' });
  }
});

// ============================================================
// POST /api/user/addresses
// Crea una nueva dirección
// ============================================================
router.post('/', authMiddleware, async (req, res) => {
  const {
    alias, tipo, nombre_receptor, telefono,
    calle, numero_ext, numero_int,
    colonia, ciudad, estado, cp,
    referencias, predeterminada
  } = req.body;

  // Validaciones básicas
  if (!nombre_receptor?.trim()) return res.status(400).json({ error: 'nombre_receptor es requerido' });
  if (!telefono?.trim() || !/^\d{10}$/.test(telefono.trim())) return res.status(400).json({ error: 'Teléfono inválido (10 dígitos)' });
  if (!calle?.trim())      return res.status(400).json({ error: 'calle es requerida' });
  if (!numero_ext?.trim()) return res.status(400).json({ error: 'numero_ext es requerido' });
  if (!colonia?.trim())    return res.status(400).json({ error: 'colonia es requerida' });
  if (!ciudad?.trim())     return res.status(400).json({ error: 'ciudad es requerida' });
  if (!estado?.trim())     return res.status(400).json({ error: 'estado es requerido' });
  if (!cp?.trim() || !/^\d{5}$/.test(cp.trim())) return res.status(400).json({ error: 'Código postal inválido (5 dígitos)' });

  try {
    const db = await getDB();

    // Verificar límite de direcciones
    const [[{ total }]] = await db.execute(
      'SELECT COUNT(*) AS total FROM user_addresses WHERE user_id = ? AND activo = 1',
      [req.user.id]
    );
    if (total >= MAX_ADDRESSES) {
      return res.status(400).json({ error: `Máximo ${MAX_ADDRESSES} direcciones permitidas` });
    }

    // Si se marca como predeterminada, quitar la actual
    if (predeterminada) {
      await db.execute(
        'UPDATE user_addresses SET predeterminada = 0 WHERE user_id = ?',
        [req.user.id]
      );
    }

    // Si es la primera dirección, hacerla predeterminada automáticamente
    const esPredet = predeterminada || total === 0;

    const [result] = await db.execute(
      `INSERT INTO user_addresses
         (user_id, alias, tipo, nombre_receptor, telefono,
          calle, numero_ext, numero_int, colonia, ciudad,
          estado, cp, referencias, predeterminada, activo, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, NOW(), NOW())`,
      [
        req.user.id,
        alias?.trim() || null,
        tipo || 'casa',
        nombre_receptor.trim(),
        telefono.trim(),
        calle.trim(),
        numero_ext.trim(),
        numero_int?.trim() || null,
        colonia.trim(),
        ciudad.trim(),
        estado.trim(),
        cp.trim(),
        referencias?.trim() || null,
        esPredet ? 1 : 0
      ]
    );

    res.status(201).json({
      message: 'Dirección creada correctamente',
      id: result.insertId
    });
  } catch (err) {
    console.error('Error creando dirección:', err);
    res.status(500).json({ error: 'Error creando dirección' });
  }
});

// ============================================================
// PUT /api/user/addresses/:id
// Actualiza una dirección existente
// ============================================================
router.put('/:id', authMiddleware, async (req, res) => {
  const {
    alias, tipo, nombre_receptor, telefono,
    calle, numero_ext, numero_int,
    colonia, ciudad, estado, cp,
    referencias, predeterminada
  } = req.body;

  // Validaciones
  if (!nombre_receptor?.trim()) return res.status(400).json({ error: 'nombre_receptor es requerido' });
  if (!telefono?.trim() || !/^\d{10}$/.test(telefono.trim())) return res.status(400).json({ error: 'Teléfono inválido' });
  if (!calle?.trim())      return res.status(400).json({ error: 'calle es requerida' });
  if (!numero_ext?.trim()) return res.status(400).json({ error: 'numero_ext es requerido' });
  if (!colonia?.trim())    return res.status(400).json({ error: 'colonia es requerida' });
  if (!ciudad?.trim())     return res.status(400).json({ error: 'ciudad es requerida' });
  if (!estado?.trim())     return res.status(400).json({ error: 'estado es requerido' });
  if (!cp?.trim() || !/^\d{5}$/.test(cp.trim())) return res.status(400).json({ error: 'Código postal inválido' });

  try {
    const db = await getDB();

    // Verificar que la dirección existe y pertenece al usuario
    const [exists] = await db.execute(
      'SELECT id FROM user_addresses WHERE id = ? AND user_id = ? AND activo = 1',
      [req.params.id, req.user.id]
    );
    if (!exists.length) return res.status(404).json({ error: 'Dirección no encontrada' });

    // Si se marca como predeterminada, quitar la actual
    if (predeterminada) {
      await db.execute(
        'UPDATE user_addresses SET predeterminada = 0 WHERE user_id = ?',
        [req.user.id]
      );
    }

    await db.execute(
      `UPDATE user_addresses SET
         alias = ?, tipo = ?, nombre_receptor = ?, telefono = ?,
         calle = ?, numero_ext = ?, numero_int = ?,
         colonia = ?, ciudad = ?, estado = ?, cp = ?,
         referencias = ?, predeterminada = ?, updated_at = NOW()
       WHERE id = ? AND user_id = ?`,
      [
        alias?.trim() || null,
        tipo || 'casa',
        nombre_receptor.trim(),
        telefono.trim(),
        calle.trim(),
        numero_ext.trim(),
        numero_int?.trim() || null,
        colonia.trim(),
        ciudad.trim(),
        estado.trim(),
        cp.trim(),
        referencias?.trim() || null,
        predeterminada ? 1 : 0,
        req.params.id,
        req.user.id
      ]
    );

    res.json({ message: 'Dirección actualizada correctamente' });
  } catch (err) {
    console.error('Error actualizando dirección:', err);
    res.status(500).json({ error: 'Error actualizando dirección' });
  }
});

// ============================================================
// PATCH /api/user/addresses/:id/default
// Marca una dirección como predeterminada
// ============================================================
router.patch('/:id/default', authMiddleware, async (req, res) => {
  try {
    const db = await getDB();

    const [exists] = await db.execute(
      'SELECT id FROM user_addresses WHERE id = ? AND user_id = ? AND activo = 1',
      [req.params.id, req.user.id]
    );
    if (!exists.length) return res.status(404).json({ error: 'Dirección no encontrada' });

    // Quitar predeterminada de todas las del usuario
    await db.execute(
      'UPDATE user_addresses SET predeterminada = 0 WHERE user_id = ?',
      [req.user.id]
    );

    // Marcar la nueva predeterminada
    await db.execute(
      'UPDATE user_addresses SET predeterminada = 1, updated_at = NOW() WHERE id = ? AND user_id = ?',
      [req.params.id, req.user.id]
    );

    res.json({ message: 'Dirección predeterminada actualizada' });
  } catch (err) {
    console.error('Error actualizando predeterminada:', err);
    res.status(500).json({ error: 'Error actualizando dirección predeterminada' });
  }
});

// ============================================================
// DELETE /api/user/addresses/:id
// Soft delete — marca activo = 0
// ============================================================
router.delete('/:id', authMiddleware, async (req, res) => {
  try {
    const db = await getDB();

    const [exists] = await db.execute(
      'SELECT id, predeterminada FROM user_addresses WHERE id = ? AND user_id = ? AND activo = 1',
      [req.params.id, req.user.id]
    );
    if (!exists.length) return res.status(404).json({ error: 'Dirección no encontrada' });

    // Soft delete
    await db.execute(
      'UPDATE user_addresses SET activo = 0, updated_at = NOW() WHERE id = ? AND user_id = ?',
      [req.params.id, req.user.id]
    );

    // Si era la predeterminada, asignar la siguiente más reciente como predeterminada
    if (exists[0].predeterminada) {
      await db.execute(
        `UPDATE user_addresses SET predeterminada = 1
         WHERE user_id = ? AND activo = 1
         ORDER BY created_at DESC LIMIT 1`,
        [req.user.id]
      );
    }

    res.json({ message: 'Dirección eliminada correctamente' });
  } catch (err) {
    console.error('Error eliminando dirección:', err);
    res.status(500).json({ error: 'Error eliminando dirección' });
  }
});

module.exports = router;