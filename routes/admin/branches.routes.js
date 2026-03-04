const express = require('express');
const router = express.Router();

const { getDB } = require('../../config/db');
const { authMiddleware, adminOnly } = require('../../middlewares/auth');
const { sanitizeInput } = require('../../helpers/validators');

// ================================
// 🏪 GET /api/admin/branches
// ================================

router.get('/', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT 
        b.id, b.nombre, b.direccion, b.telefono, b.activo, b.createdAt,
        COUNT(DISTINCT i.product_id) AS productos,
        COALESCE(SUM(i.stock), 0) AS stock_total
      FROM branches b
      LEFT JOIN inventory i ON i.branch_id = b.id
      GROUP BY b.id ORDER BY b.nombre
    `);
    res.json(rows);
  } catch (err) {
    console.error('Error obteniendo sucursales:', err);
    res.status(500).json({ error: 'Error obteniendo sucursales' });
  }
});

// ================================
// ➕ POST /api/admin/branches
// ================================

router.post('/', authMiddleware, adminOnly, async (req, res) => {
  const { nombre, direccion, telefono } = req.body;

  if (!nombre || !direccion) {
    return res.status(400).json({ error: 'Nombre y dirección obligatorios' });
  }

  const nombreSafe    = sanitizeInput(nombre);
  const direccionSafe = sanitizeInput(direccion);
  const telefonoSafe  = telefono ? sanitizeInput(telefono) : null;

  try {
    const db = await getDB();

    const [exists] = await db.execute('SELECT id FROM branches WHERE nombre = ?', [nombreSafe]);
    if (exists.length > 0) return res.status(400).json({ error: 'Ya existe una sucursal con ese nombre' });

    await db.execute(
      'INSERT INTO branches (nombre, direccion, telefono, activo, createdAt) VALUES (?, ?, ?, 1, NOW())',
      [nombreSafe, direccionSafe, telefonoSafe]
    );

    console.log(`✅ Sucursal creada: ${nombreSafe} por ${req.user.usuario}`);
    res.json({ message: 'Sucursal creada correctamente' });
  } catch (err) {
    console.error('Error creando sucursal:', err);
    res.status(500).json({ error: 'Error creando sucursal' });
  }
});

// ================================
// ✏️ PUT /api/admin/branches/:id
// ================================

router.put('/:id', authMiddleware, adminOnly, async (req, res) => {
  const { nombre, direccion, telefono, activo } = req.body;

  if (!nombre || !direccion) {
    return res.status(400).json({ error: 'Nombre y dirección obligatorios' });
  }

  const nombreSafe    = sanitizeInput(nombre);
  const direccionSafe = sanitizeInput(direccion);
  const telefonoSafe  = telefono ? sanitizeInput(telefono) : null;

  try {
    const db = await getDB();

    const [exists] = await db.execute('SELECT id FROM branches WHERE id = ?', [req.params.id]);
    if (exists.length === 0) return res.status(404).json({ error: 'Sucursal no encontrada' });

    await db.execute(
      'UPDATE branches SET nombre=?, direccion=?, telefono=?, activo=? WHERE id=?',
      [nombreSafe, direccionSafe, telefonoSafe, activo, req.params.id]
    );

    console.log(`✅ Sucursal actualizada: ID ${req.params.id} por ${req.user.usuario}`);
    res.json({ message: 'Sucursal actualizada correctamente' });
  } catch (err) {
    console.error('Error actualizando sucursal:', err);
    res.status(500).json({ error: 'Error actualizando sucursal' });
  }
});

// ================================
// 🗑️ DELETE /api/admin/branches/:id
// ================================

router.delete('/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();

    const [exists] = await db.execute('SELECT id, nombre FROM branches WHERE id = ?', [req.params.id]);
    if (exists.length === 0) return res.status(404).json({ error: 'Sucursal no encontrada' });

    const [inventory] = await db.execute('SELECT COUNT(*) as total FROM inventory WHERE branch_id = ?', [req.params.id]);
    if (inventory[0].total > 0) {
      return res.status(400).json({ error: 'No se puede eliminar una sucursal con inventario. Elimine o transfiera el inventario primero.' });
    }

    await db.execute('UPDATE branches SET activo = 0 WHERE id = ?', [req.params.id]);

    console.log(`⚠️ Sucursal desactivada: ${exists[0].nombre} por ${req.user.usuario}`);
    res.json({ message: 'Sucursal desactivada correctamente' });
  } catch (err) {
    console.error('Error eliminando sucursal:', err);
    res.status(500).json({ error: 'Error eliminando sucursal' });
  }
});

module.exports = router;
