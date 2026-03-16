const express = require('express');
const router  = express.Router();

const { getDB }                      = require('../../config/db');
const { authMiddleware, adminOnly }  = require('../../middlewares/auth');
const { sanitizeInput }              = require('../../helpers/validators');
const { sanitizeLog }                = require('../../helpers/sanitizeLog');

// ================================
// 📊 GET /api/admin/products/stats/summary
// ================================

router.get('/stats/summary', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();

    const [stats] = await db.execute(`
      SELECT COUNT(*) AS total_productos,
             SUM(CASE WHEN activo=1 THEN 1 ELSE 0 END) AS activos,
             SUM(CASE WHEN activo=0 THEN 1 ELSE 0 END) AS inactivos,
             COUNT(DISTINCT categoria)                  AS total_categorias,
             COUNT(DISTINCT marca)                      AS total_marcas,
             AVG(precio)                                AS precio_promedio,
             MIN(precio)                                AS precio_minimo,
             MAX(precio)                                AS precio_maximo
      FROM products
    `);

    const [porCategoria] = await db.execute(`
      SELECT categoria, COUNT(*) AS productos,
             SUM(CASE WHEN activo=1 THEN 1 ELSE 0 END) AS activos
      FROM products
      WHERE categoria IS NOT NULL AND categoria != ''
      GROUP BY categoria ORDER BY productos DESC LIMIT 10
    `);

    const [porMarca] = await db.execute(`
      SELECT marca, COUNT(*) AS productos,
             SUM(CASE WHEN activo=1 THEN 1 ELSE 0 END) AS activos
      FROM products
      WHERE marca IS NOT NULL AND marca != ''
      GROUP BY marca ORDER BY productos DESC LIMIT 10
    `);

    res.json({ ...stats[0], porCategoria, porMarca });
  } catch (err) {
    res.status(500).json({ error: 'Error obteniendo estadísticas', detalle: err.message });
  }
});

// ================================
// 🔍 GET /api/admin/products/search
// Usa v_productos_stock — ya tiene stock_total y sucursales_con_stock
// ================================

router.get('/search', authMiddleware, adminOnly, async (req, res) => {
  const { q, categoria, marca, activo } = req.query;

  try {
    const db = await getDB();

    // La vista v_productos_stock ya calcula stock_total, sucursales_con_stock,
    // stock_minimo_sucursal y sucursales_bajo_stock sin necesitar el LEFT JOIN
    let sql    = 'SELECT * FROM v_productos_stock WHERE 1=1';
    const params = [];

    if (q) {
      sql += ' AND (nombre LIKE ? OR descripcion LIKE ?)';
      params.push(`%${q}%`, `%${q}%`);
    }
    if (categoria)            { sql += ' AND categoria = ?'; params.push(categoria); }
    if (marca)                { sql += ' AND marca = ?';     params.push(marca);     }
    if (activo !== undefined) { sql += ' AND activo = ?';    params.push(activo);    }

    sql += ' ORDER BY nombre';

    const [rows] = await db.execute(sql, params);
    res.json(rows);
  } catch (err) {
    console.error('Error buscando productos:', err);
    res.status(500).json({ error: 'Error buscando productos' });
  }
});

// ================================
// 📂 GET /api/admin/products/categories
// ================================

router.get('/categories', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT DISTINCT categoria AS nombre, COUNT(*) AS productos
      FROM products
      WHERE categoria IS NOT NULL AND categoria != ''
      GROUP BY categoria ORDER BY categoria
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Error obteniendo categorías' });
  }
});

// ================================
// 🏷️ GET /api/admin/products/marcas
// ================================

router.get('/marcas', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT DISTINCT marca AS nombre, COUNT(*) AS productos
      FROM products
      WHERE marca IS NOT NULL AND marca != ''
      GROUP BY marca ORDER BY marca
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Error obteniendo marcas' });
  }
});

// ================================
// 📦 GET /api/admin/products
// Usa v_productos_stock — evita el GROUP BY + JOIN manual
// ================================

router.get('/', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();

    // La vista ya tiene: stock_total, sucursales_con_stock,
    // stock_minimo_sucursal, sucursales_bajo_stock, createdAt, updatedAt
    const [rows] = await db.execute(`
      SELECT * FROM v_productos_stock
      ORDER BY id DESC
    `);

    res.json(rows);
  } catch (err) {
    console.error('Error obteniendo productos:', err);
    res.status(500).json({ error: 'Error obteniendo productos' });
  }
});

// ================================
// 🔎 GET /api/admin/products/:id
// ================================

router.get('/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();

    // Producto con stock_total desde la vista
    const [rows] = await db.execute(
      'SELECT * FROM v_productos_stock WHERE id = ?',
      [req.params.id]
    );
    if (rows.length === 0)
      return res.status(404).json({ error: 'Producto no encontrado' });

    // Inventario detallado por sucursal desde v_inventario_completo
    const [inventory] = await db.execute(`
      SELECT id, stock, min_stock, branch_id, sucursal, estado, valor_stock
      FROM v_inventario_completo
      WHERE product_id = ?
      ORDER BY sucursal
    `, [req.params.id]);

    res.json({ product: rows[0], inventory });
  } catch (err) {
    console.error('Error obteniendo producto:', err);
    res.status(500).json({ error: 'Error obteniendo producto' });
  }
});

// ================================
// ➕ POST /api/admin/products
// ================================

router.post('/', authMiddleware, adminOnly, async (req, res) => {
  const { nombre, marca, descripcion, precio, categoria, imagen, talla, colores, inventario } = req.body;

  if (!nombre || !precio)
    return res.status(400).json({ error: 'Nombre y precio obligatorios' });
  if (precio < 0)
    return res.status(400).json({ error: 'El precio no puede ser negativo' });

  const nombreSafe      = sanitizeInput(nombre);
  const marcaSafe       = marca       ? sanitizeInput(marca)       : null;
  const descripcionSafe = descripcion ? sanitizeInput(descripcion) : null;
  const categoriaSafe   = categoria   ? sanitizeInput(categoria)   : null;
  const tallaSafe       = talla       ? sanitizeInput(talla)       : null;
  const coloresSafe     = colores     ? sanitizeInput(colores)     : null;

  try {
    const db = await getDB();

    const [result] = await db.execute(`
      INSERT INTO products (nombre, marca, descripcion, precio, categoria, imagen, talla, colores, activo, createdAt, updatedAt)
      VALUES (?,?,?,?,?,?,?,?,1,NOW(),NOW())
    `, [nombreSafe, marcaSafe, descripcionSafe, precio, categoriaSafe, imagen, tallaSafe, coloresSafe]);

    const productId = result.insertId;

    if (inventario && Array.isArray(inventario)) {
      for (const inv of inventario) {
        if (inv.branch_id && inv.stock !== undefined) {
          await db.execute(`
            INSERT INTO inventory (product_id, branch_id, stock, min_stock)
            VALUES (?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE stock = VALUES(stock), min_stock = VALUES(min_stock)
          `, [productId, inv.branch_id, inv.stock, inv.min_stock || 10]);
        }
      }
    }

    console.log(`✅ Producto creado: ${sanitizeLog(nombreSafe)} (ID: ${sanitizeLog(productId)}) por ${sanitizeLog(req.user.usuario)}`);
    res.json({ message: 'Producto creado correctamente', productId });
  } catch (err) {
    console.error('Error creando producto:', err);
    res.status(500).json({ error: 'Error creando producto' });
  }
});

// ================================
// ✏️ PUT /api/admin/products/:id
// ================================

router.put('/:id', authMiddleware, adminOnly, async (req, res) => {
  const { nombre, marca, descripcion, precio, categoria, imagen, talla, colores, activo } = req.body;

  if (!nombre || precio === undefined)
    return res.status(400).json({ error: 'Nombre y precio son obligatorios' });
  if (precio < 0)
    return res.status(400).json({ error: 'El precio no puede ser negativo' });

  const nombreSafe      = sanitizeInput(nombre);
  const marcaSafe       = marca       ? sanitizeInput(marca)       : null;
  const descripcionSafe = descripcion ? sanitizeInput(descripcion) : null;
  const categoriaSafe   = categoria   ? sanitizeInput(categoria)   : null;
  const tallaSafe       = talla       ? sanitizeInput(talla)       : null;
  const coloresSafe     = colores     ? sanitizeInput(colores)     : null;

  try {
    const db = await getDB();
    const [exists] = await db.execute('SELECT id FROM products WHERE id = ?', [req.params.id]);
    if (exists.length === 0)
      return res.status(404).json({ error: 'Producto no encontrado' });

    await db.execute(`
      UPDATE products
      SET nombre=?, marca=?, descripcion=?, precio=?, categoria=?,
          imagen=?, talla=?, colores=?, activo=?, updatedAt=NOW()
      WHERE id=?
    `, [nombreSafe, marcaSafe, descripcionSafe, precio, categoriaSafe, imagen, tallaSafe, coloresSafe, activo, req.params.id]);

    console.log(`✅ Producto actualizado: ID ${sanitizeLog(req.params.id)} por ${sanitizeLog(req.user.usuario)}`);
    res.json({ message: 'Producto actualizado correctamente' });
  } catch (err) {
    console.error('Error actualizando producto:', err);
    res.status(500).json({ error: 'Error actualizando producto' });
  }
});

// ================================
// 🏪 PUT /api/admin/products/:id/inventory
// ================================

router.put('/:id/inventory', authMiddleware, adminOnly, async (req, res) => {
  const { inventario } = req.body;

  if (!inventario || !Array.isArray(inventario))
    return res.status(400).json({ error: 'Debe proporcionar un array de inventario' });

  try {
    const db = await getDB();
    const [exists] = await db.execute('SELECT id FROM products WHERE id = ?', [req.params.id]);
    if (exists.length === 0)
      return res.status(404).json({ error: 'Producto no encontrado' });

    for (const inv of inventario) {
      if (inv.branch_id && inv.stock !== undefined) {
        await db.execute(`
          INSERT INTO inventory (product_id, branch_id, stock, min_stock)
          VALUES (?, ?, ?, ?)
          ON DUPLICATE KEY UPDATE stock = VALUES(stock), min_stock = VALUES(min_stock)
        `, [req.params.id, inv.branch_id, inv.stock, inv.min_stock || 10]);
      }
    }

    console.log(`✅ Inventario actualizado para producto ID ${sanitizeLog(req.params.id)} por ${sanitizeLog(req.user.usuario)}`);
    res.json({ message: 'Inventario actualizado correctamente' });
  } catch (err) {
    console.error('Error actualizando inventario del producto:', err);
    res.status(500).json({ error: 'Error actualizando inventario' });
  }
});

// ================================
// 🔄 PATCH /api/admin/products/:id/reactivate
// ================================

router.patch('/:id/reactivate', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const [exists] = await db.execute('SELECT id, nombre FROM products WHERE id = ?', [req.params.id]);
    if (exists.length === 0)
      return res.status(404).json({ error: 'Producto no encontrado' });

    await db.execute('UPDATE products SET activo = 1, updatedAt = NOW() WHERE id = ?', [req.params.id]);

    console.log(`✅ Producto reactivado: ${sanitizeLog(exists[0].nombre)} por ${sanitizeLog(req.user.usuario)}`);
    res.json({ message: 'Producto reactivado correctamente' });
  } catch (err) {
    res.status(500).json({ error: 'Error reactivando producto' });
  }
});

// ================================
// 🗑️ DELETE /api/admin/products/:id  (soft delete)
// ================================

router.delete('/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const [exists] = await db.execute('SELECT id, nombre FROM products WHERE id = ?', [req.params.id]);
    if (exists.length === 0)
      return res.status(404).json({ error: 'Producto no encontrado' });

    await db.execute('UPDATE products SET activo = 0, updatedAt = NOW() WHERE id = ?', [req.params.id]);

    console.log(`⚠️ Producto desactivado: ${sanitizeLog(exists[0].nombre)} por ${sanitizeLog(req.user.usuario)}`);
    res.json({ message: 'Producto desactivado correctamente' });
  } catch (err) {
    res.status(500).json({ error: 'Error eliminando producto' });
  }
});

// ================================
// 🗑️ DELETE /api/admin/products/:id/permanent
// ================================

router.delete('/:id/permanent', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const [exists] = await db.execute('SELECT id, nombre FROM products WHERE id = ?', [req.params.id]);
    if (exists.length === 0)
      return res.status(404).json({ error: 'Producto no encontrado' });

    await db.execute('DELETE FROM inventory WHERE product_id = ?', [req.params.id]);
    await db.execute('DELETE FROM products WHERE id = ?', [req.params.id]);

    console.log(`🗑️ Producto eliminado permanentemente: ${sanitizeLog(exists[0].nombre)} por ${sanitizeLog(req.user.usuario)}`);
    res.json({ message: 'Producto eliminado permanentemente' });
  } catch (err) {
    res.status(500).json({ error: 'Error eliminando producto permanentemente' });
  }
});

module.exports = router;