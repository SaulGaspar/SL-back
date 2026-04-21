// routes/public/address.js
const express = require('express');
const router  = express.Router();
const { getDB }          = require('../../config/db');
const { authMiddleware } = require('../../middlewares/auth');

const MAX_ADDRESSES = 10;

// ── GET /api/user/addresses ──────────────────────────────────
router.get('/', authMiddleware, async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(
      `SELECT * FROM direcciones
       WHERE usuario_id = ?
       ORDER BY predeterminada DESC, creado_en DESC`,
      [req.user.id]
    );
    res.json(rows);
  } catch (err) {
    console.error('Error obteniendo direcciones:', err);
    res.status(500).json({ error: 'Error obteniendo direcciones' });
  }
});

// ── GET /api/user/addresses/:id ──────────────────────────────
router.get('/:id', authMiddleware, async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(
      `SELECT * FROM direcciones WHERE id = ? AND usuario_id = ?`,
      [req.params.id, req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Dirección no encontrada' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Error obteniendo dirección' });
  }
});

// ── POST /api/user/addresses ─────────────────────────────────
router.post('/', authMiddleware, async (req, res) => {
  const {
    alias, tipo, nombre_receptor, telefono,
    calle, numero_ext, numero_int,
    colonia, ciudad, estado, cp,
    referencias, predeterminada
  } = req.body;

  if (!nombre_receptor?.trim())  return res.status(400).json({ error: 'nombre_receptor es requerido' });
  if (!telefono?.trim() || !/^\d{10}$/.test(telefono.trim())) return res.status(400).json({ error: 'Teléfono inválido (10 dígitos)' });
  if (!calle?.trim())            return res.status(400).json({ error: 'calle es requerida' });
  if (!numero_ext?.trim())       return res.status(400).json({ error: 'numero_ext es requerido' });
  if (!colonia?.trim())          return res.status(400).json({ error: 'colonia es requerida' });
  if (!ciudad?.trim())           return res.status(400).json({ error: 'ciudad es requerida' });
  if (!estado?.trim())           return res.status(400).json({ error: 'estado es requerido' });
  if (!cp?.trim() || !/^\d{5}$/.test(cp.trim())) return res.status(400).json({ error: 'Código postal inválido (5 dígitos)' });

  try {
    const db = await getDB();

    const [[{ total }]] = await db.execute(
      'SELECT COUNT(*) AS total FROM direcciones WHERE usuario_id = ?',
      [req.user.id]
    );
    if (total >= MAX_ADDRESSES) {
      return res.status(400).json({ error: `Máximo ${MAX_ADDRESSES} direcciones permitidas` });
    }

    // Si se marca como predeterminada, quitar la actual
    if (predeterminada || total === 0) {
      await db.execute(
        'UPDATE direcciones SET predeterminada = 0 WHERE usuario_id = ?',
        [req.user.id]
      );
    }

    const esPredet = predeterminada || total === 0;

    const [result] = await db.execute(
      `INSERT INTO direcciones
         (usuario_id, alias, tipo, nombre_receptor, telefono,
          calle, numero_ext, numero_int, colonia, ciudad,
          estado, cp, referencias, predeterminada)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        req.user.id,
        alias?.trim()        || null,
        tipo                 || 'casa',
        nombre_receptor.trim(),
        telefono.trim(),
        calle.trim(),
        numero_ext.trim(),
        numero_int?.trim()   || null,
        colonia.trim(),
        ciudad.trim(),
        estado.trim(),
        cp.trim(),
        referencias?.trim()  || null,
        esPredet ? 1 : 0
      ]
    );

    const [rows] = await db.execute(
      'SELECT * FROM direcciones WHERE id = ?', [result.insertId]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    console.error('Error creando dirección:', err);
    res.status(500).json({ error: 'Error creando dirección' });
  }
});

// ── PUT /api/user/addresses/:id ──────────────────────────────
router.put('/:id', authMiddleware, async (req, res) => {
  const {
    alias, tipo, nombre_receptor, telefono,
    calle, numero_ext, numero_int,
    colonia, ciudad, estado, cp,
    referencias, predeterminada
  } = req.body;

  if (!nombre_receptor?.trim())  return res.status(400).json({ error: 'nombre_receptor es requerido' });
  if (!telefono?.trim() || !/^\d{10}$/.test(telefono.trim())) return res.status(400).json({ error: 'Teléfono inválido' });
  if (!calle?.trim())            return res.status(400).json({ error: 'calle es requerida' });
  if (!numero_ext?.trim())       return res.status(400).json({ error: 'numero_ext es requerido' });
  if (!colonia?.trim())          return res.status(400).json({ error: 'colonia es requerida' });
  if (!ciudad?.trim())           return res.status(400).json({ error: 'ciudad es requerida' });
  if (!estado?.trim())           return res.status(400).json({ error: 'estado es requerido' });
  if (!cp?.trim() || !/^\d{5}$/.test(cp.trim())) return res.status(400).json({ error: 'Código postal inválido' });

  try {
    const db = await getDB();

    const [exists] = await db.execute(
      'SELECT id FROM direcciones WHERE id = ? AND usuario_id = ?',
      [req.params.id, req.user.id]
    );
    if (!exists.length) return res.status(404).json({ error: 'Dirección no encontrada' });

    if (predeterminada) {
      await db.execute(
        'UPDATE direcciones SET predeterminada = 0 WHERE usuario_id = ?',
        [req.user.id]
      );
    }

    await db.execute(
      `UPDATE direcciones SET
         alias = ?, tipo = ?, nombre_receptor = ?, telefono = ?,
         calle = ?, numero_ext = ?, numero_int = ?,
         colonia = ?, ciudad = ?, estado = ?, cp = ?,
         referencias = ?, predeterminada = ?
       WHERE id = ? AND usuario_id = ?`,
      [
        alias?.trim()       || null,
        tipo                || 'casa',
        nombre_receptor.trim(),
        telefono.trim(),
        calle.trim(),
        numero_ext.trim(),
        numero_int?.trim()  || null,
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

    const [rows] = await db.execute(
      'SELECT * FROM direcciones WHERE id = ?', [req.params.id]
    );
    res.json(rows[0]);
  } catch (err) {
    console.error('Error actualizando dirección:', err);
    res.status(500).json({ error: 'Error actualizando dirección' });
  }
});

// ── PATCH /api/user/addresses/:id/default ───────────────────
router.patch('/:id/default', authMiddleware, async (req, res) => {
  try {
    const db = await getDB();

    const [exists] = await db.execute(
      'SELECT id FROM direcciones WHERE id = ? AND usuario_id = ?',
      [req.params.id, req.user.id]
    );
    if (!exists.length) return res.status(404).json({ error: 'Dirección no encontrada' });

    await db.execute(
      'UPDATE direcciones SET predeterminada = 0 WHERE usuario_id = ?',
      [req.user.id]
    );
    await db.execute(
      'UPDATE direcciones SET predeterminada = 1 WHERE id = ? AND usuario_id = ?',
      [req.params.id, req.user.id]
    );

    res.json({ message: 'Dirección predeterminada actualizada' });
  } catch (err) {
    console.error('Error actualizando predeterminada:', err);
    res.status(500).json({ error: 'Error actualizando dirección predeterminada' });
  }
});

// ── DELETE /api/user/addresses/:id ──────────────────────────
router.delete('/:id', authMiddleware, async (req, res) => {
  try {
    const db = await getDB();

    const [exists] = await db.execute(
      'SELECT id, predeterminada FROM direcciones WHERE id = ? AND usuario_id = ?',
      [req.params.id, req.user.id]
    );
    if (!exists.length) return res.status(404).json({ error: 'Dirección no encontrada' });

    await db.execute(
      'DELETE FROM direcciones WHERE id = ? AND usuario_id = ?',
      [req.params.id, req.user.id]
    );

    // Si era la predeterminada, asignar la más reciente como nueva predeterminada
    if (exists[0].predeterminada) {
      await db.execute(
        `UPDATE direcciones SET predeterminada = 1
         WHERE usuario_id = ?
         ORDER BY creado_en DESC LIMIT 1`,
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