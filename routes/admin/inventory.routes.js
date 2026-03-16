const express = require('express');
const router  = express.Router();

const { getDB }                      = require('../../config/db');
const { authMiddleware, adminOnly }  = require('../../middlewares/auth');

// ================================
// 📦 GET /api/admin/inventory
// Usa la vista v_inventario_completo
// ================================

router.get('/', authMiddleware, adminOnly, async (req, res) => {
  const { branch, low_stock } = req.query;

  try {
    const db = await getDB();

    // v_inventario_completo ya tiene el JOIN triple inventory+products+branches
    // y calcula el campo "estado" automáticamente
    let sql    = `SELECT * FROM v_inventario_completo WHERE 1=1`;
    const params = [];

    if (branch && branch !== 'all') {
      sql += ' AND branch_id = ?';
      params.push(branch);
    }
    if (low_stock === 'true') {
      sql += ' AND estado = \'bajo_stock\'';
    }

    sql += ' ORDER BY sucursal, producto';

    const [rows] = await db.execute(sql, params);
    res.json(rows);
  } catch (err) {
    console.error('Error obteniendo inventario:', err);
    res.status(500).json({ error: 'Error obteniendo inventario' });
  }
});

// ================================
// 📊 GET /api/admin/inventory/stats
// Usa la vista v_inventario_completo para los stats
// ================================

router.get('/stats', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();

    // Stats generales desde la vista — un solo query en lugar de dos
    const [stats] = await db.execute(`
      SELECT
        COUNT(DISTINCT product_id)                                          AS total_productos,
        COUNT(DISTINCT branch_id)                                           AS total_sucursales,
        SUM(stock)                                                          AS stock_total,
        SUM(CASE WHEN estado = 'sin_stock'  THEN 1 ELSE 0 END)             AS productos_sin_stock,
        SUM(CASE WHEN estado = 'bajo_stock' THEN 1 ELSE 0 END)             AS productos_bajo_stock,
        SUM(valor_stock)                                                    AS valor_inventario
      FROM v_inventario_completo
    `);

    // Resumen por sucursal (también desde la vista)
    const [porSucursal] = await db.execute(`
      SELECT
        sucursal,
        COUNT(DISTINCT product_id) AS productos,
        SUM(stock)                 AS stock_total,
        SUM(valor_stock)           AS valor_inventario
      FROM v_inventario_completo
      GROUP BY branch_id, sucursal
      ORDER BY valor_inventario DESC
    `);

    res.json({ general: stats[0], porSucursal });
  } catch (err) {
    console.error('Error obteniendo estadísticas de inventario:', err);
    res.status(500).json({ error: 'Error obteniendo estadísticas' });
  }
});

// ================================
// ➕ POST /api/admin/inventory
// ================================

router.post('/', authMiddleware, adminOnly, async (req, res) => {
  const { product_id, branch_id, stock, min_stock } = req.body;

  if (!product_id || !branch_id || stock === undefined)
    return res.status(400).json({ error: 'Faltan campos obligatorios' });
  if (stock < 0)
    return res.status(400).json({ error: 'El stock no puede ser negativo' });

  try {
    const db = await getDB();

    const [product] = await db.execute(
      'SELECT id, nombre, activo FROM products WHERE id = ?', [product_id]
    );
    if (product.length === 0)    return res.status(404).json({ error: 'Producto no encontrado' });
    if (product[0].activo === 0) return res.status(400).json({ error: 'No se puede agregar inventario a un producto inactivo' });

    const [branch] = await db.execute(
      'SELECT id, nombre FROM branches WHERE id = ?', [branch_id]
    );
    if (branch.length === 0) return res.status(404).json({ error: 'Sucursal no encontrada' });

    // Usamos la vista para verificar duplicado (más limpio que consultar inventory directamente)
    const [exists] = await db.execute(
      'SELECT id FROM inventory WHERE product_id = ? AND branch_id = ?',
      [product_id, branch_id]
    );
    if (exists.length > 0)
      return res.status(400).json({ error: 'Este producto ya tiene inventario en esta sucursal. Use actualizar en su lugar.' });

    await db.execute(
      'INSERT INTO inventory (product_id, branch_id, stock, min_stock) VALUES (?, ?, ?, ?)',
      [product_id, branch_id, stock, min_stock || 10]
    );

    console.log(`✅ Inventario creado: ${product[0].nombre} en ${branch[0].nombre} por ${req.user.usuario}`);
    res.json({ message: 'Inventario agregado correctamente' });
  } catch (err) {
    console.error('Error agregando inventario:', err);
    res.status(500).json({ error: 'Error agregando inventario' });
  }
});

// ================================
// ✏️ PUT /api/admin/inventory/:id
// ================================

router.put('/:id', authMiddleware, adminOnly, async (req, res) => {
  const { stock, min_stock } = req.body;

  if (stock === undefined || stock < 0)
    return res.status(400).json({ error: 'Stock inválido' });
  if (min_stock !== undefined && min_stock < 0)
    return res.status(400).json({ error: 'Stock mínimo inválido' });

  try {
    const db = await getDB();

    // La vista nos da nombre de producto y sucursal sin JOIN manual
    const [exists] = await db.execute(
      'SELECT id, producto, sucursal FROM v_inventario_completo WHERE id = ?',
      [req.params.id]
    );
    if (exists.length === 0)
      return res.status(404).json({ error: 'Registro de inventario no encontrado' });

    await db.execute(
      'UPDATE inventory SET stock = ?, min_stock = ? WHERE id = ?',
      [stock, min_stock || 10, req.params.id]
    );

    console.log(`✅ Inventario actualizado: ${exists[0].producto} en ${exists[0].sucursal} por ${req.user.usuario}`);
    res.json({ message: 'Inventario actualizado correctamente' });
  } catch (err) {
    console.error('Error actualizando inventario:', err);
    res.status(500).json({ error: 'Error actualizando inventario' });
  }
});

// ================================
// 🗑️ DELETE /api/admin/inventory/:id
// ================================

router.delete('/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();

    const [exists] = await db.execute(
      'SELECT id, producto, sucursal FROM v_inventario_completo WHERE id = ?',
      [req.params.id]
    );
    if (exists.length === 0)
      return res.status(404).json({ error: 'Registro de inventario no encontrado' });

    await db.execute('DELETE FROM inventory WHERE id = ?', [req.params.id]);

    console.log(`🗑️ Inventario eliminado: ${exists[0].producto} de ${exists[0].sucursal} por ${req.user.usuario}`);
    res.json({ message: 'Inventario eliminado correctamente' });
  } catch (err) {
    console.error('Error eliminando inventario:', err);
    res.status(500).json({ error: 'Error eliminando inventario' });
  }
});

// ================================
// 🔄 POST /api/admin/inventory/transfer
// ================================

router.post('/transfer', authMiddleware, adminOnly, async (req, res) => {
  const { product_id, from_branch_id, to_branch_id, cantidad } = req.body;

  if (!product_id || !from_branch_id || !to_branch_id || !cantidad)
    return res.status(400).json({ error: 'Faltan campos obligatorios' });
  if (cantidad <= 0)
    return res.status(400).json({ error: 'La cantidad debe ser mayor a 0' });
  if (from_branch_id === to_branch_id)
    return res.status(400).json({ error: 'No se puede transferir a la misma sucursal' });

  try {
    const db = await getDB();
    await db.execute('START TRANSACTION');

    try {
      // Consultar origen desde la vista (ya tiene stock, nombre de sucursal y producto)
      const [origen] = await db.execute(
        `SELECT id, stock, sucursal, producto
         FROM v_inventario_completo
         WHERE product_id = ? AND branch_id = ?`,
        [product_id, from_branch_id]
      );

      if (origen.length === 0) throw new Error('No existe inventario en la sucursal origen');
      if (origen[0].stock < cantidad)
        throw new Error(`Stock insuficiente en ${origen[0].sucursal}. Disponible: ${origen[0].stock}`);

      const [destino] = await db.execute(
        'SELECT id FROM inventory WHERE product_id = ? AND branch_id = ?',
        [product_id, to_branch_id]
      );

      await db.execute(
        'UPDATE inventory SET stock = stock - ? WHERE id = ?',
        [cantidad, origen[0].id]
      );

      if (destino.length > 0) {
        await db.execute(
          'UPDATE inventory SET stock = stock + ? WHERE id = ?',
          [cantidad, destino[0].id]
        );
      } else {
        await db.execute(
          'INSERT INTO inventory (product_id, branch_id, stock, min_stock) VALUES (?, ?, ?, 10)',
          [product_id, to_branch_id, cantidad]
        );
      }

      await db.execute('COMMIT');
      console.log(`✅ Transferencia: ${cantidad} unidades de ${origen[0].producto} por ${req.user.usuario}`);
      res.json({ message: 'Transferencia completada exitosamente' });

    } catch (error) {
      await db.execute('ROLLBACK');
      throw error;
    }
  } catch (err) {
    console.error('Error en transferencia:', err);
    res.status(500).json({ error: err.message || 'Error realizando transferencia' });
  }
});

// ================================
// ➕ POST /api/admin/inventory/batch
// Upsert masivo — una sola conexión
// ================================

router.post('/batch', authMiddleware, adminOnly, async (req, res) => {
  const { items } = req.body;

  if (!Array.isArray(items) || items.length === 0)
    return res.status(400).json({ error: 'Se requiere un array items no vacío' });

  try {
    const db = await getDB();
    let created = 0, updated = 0, errors = 0;

    for (const item of items) {
      const { product_id, branch_id, stock, min_stock } = item;
      if (!product_id || !branch_id || stock === undefined) { errors++; continue; }

      try {
        const [exists] = await db.execute(
          'SELECT id FROM inventory WHERE product_id = ? AND branch_id = ?',
          [product_id, branch_id]
        );

        if (exists.length > 0) {
          await db.execute(
            'UPDATE inventory SET stock = ?, min_stock = ? WHERE product_id = ? AND branch_id = ?',
            [stock, min_stock || 40, product_id, branch_id]
          );
          updated++;
        } else {
          const [product] = await db.execute(
            'SELECT id, activo FROM products WHERE id = ?', [product_id]
          );
          if (product.length === 0 || product[0].activo === 0) { errors++; continue; }

          await db.execute(
            'INSERT INTO inventory (product_id, branch_id, stock, min_stock) VALUES (?, ?, ?, ?)',
            [product_id, branch_id, stock, min_stock || 40]
          );
          created++;
        }
      } catch (itemErr) {
        console.error(`Error en item product_id=${product_id} branch_id=${branch_id}:`, itemErr.message);
        errors++;
      }
    }

    console.log(`✅ Batch inventory: ${created} creados, ${updated} actualizados, ${errors} errores`);
    res.json({ created, updated, errors, total: items.length });

  } catch (err) {
    console.error('Error en batch inventory:', err);
    res.status(500).json({ error: 'Error en importación batch' });
  }
});

// ================================
// ✏️ PUT /api/admin/inventory/batch-update
// Actualización masiva — una sola conexión
// ================================

router.put('/batch-update', authMiddleware, adminOnly, async (req, res) => {
  const { items } = req.body;

  if (!Array.isArray(items) || items.length === 0)
    return res.status(400).json({ error: 'Se requiere un array items no vacío' });

  try {
    const db = await getDB();
    let updated = 0, errors = 0;

    for (const item of items) {
      const { id, stock, min_stock } = item;
      if (!id || stock === undefined) { errors++; continue; }
      try {
        await db.execute(
          'UPDATE inventory SET stock = ?, min_stock = ? WHERE id = ?',
          [stock, min_stock || 40, id]
        );
        updated++;
      } catch (itemErr) {
        console.error(`Error actualizando id=${id}:`, itemErr.message);
        errors++;
      }
    }

    console.log(`✅ Batch update inventory: ${updated} actualizados, ${errors} errores`);
    res.json({ updated, errors, total: items.length });

  } catch (err) {
    console.error('Error en batch-update inventory:', err);
    res.status(500).json({ error: 'Error en actualización batch' });
  }
});

module.exports = router;