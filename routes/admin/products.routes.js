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
// ================================

router.get('/search', authMiddleware, adminOnly, async (req, res) => {
  const { q, categoria, marca, activo } = req.query;

  try {
    const db = await getDB();

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
// ================================

router.get('/', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
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

    const [rows] = await db.execute(
      'SELECT * FROM v_productos_stock WHERE id = ?',
      [req.params.id]
    );
    if (rows.length === 0)
      return res.status(404).json({ error: 'Producto no encontrado' });

    const [inventory] = await db.execute(`
      SELECT id, stock, min_stock, branch_id, sucursal, estado, valor_stock
      FROM v_inventario_completo
      WHERE product_id = ?
      ORDER BY sucursal
    `, [req.params.id]);

    // Imágenes adicionales
    const [images] = await db.execute(`
      SELECT id, url, orden FROM product_images
      WHERE product_id = ? ORDER BY orden ASC
    `, [req.params.id]);

    res.json({ product: rows[0], inventory, images });
  } catch (err) {
    console.error('Error obteniendo producto:', err);
    res.status(500).json({ error: 'Error obteniendo producto' });
  }
});

// ================================
// 🖼️ GET /api/admin/products/:id/images
// Obtener todas las imágenes de un producto
// ================================

router.get('/:id/images', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const [images] = await db.execute(`
      SELECT id, url, orden, created_at
      FROM product_images
      WHERE product_id = ?
      ORDER BY orden ASC
    `, [req.params.id]);
    res.json(images);
  } catch (err) {
    console.error('Error obteniendo imágenes:', err);
    res.status(500).json({ error: 'Error obteniendo imágenes' });
  }
});

// ================================
// 🖼️ POST /api/admin/products/:id/images
// Agregar imagen a un producto
// ================================

router.post('/:id/images', authMiddleware, adminOnly, async (req, res) => {
  const { url, orden } = req.body;
  if (!url) return res.status(400).json({ error: 'URL de imagen requerida' });

  try {
    const db = await getDB();

    // Verificar que el producto existe
    const [exists] = await db.execute('SELECT id FROM products WHERE id = ?', [req.params.id]);
    if (exists.length === 0)
      return res.status(404).json({ error: 'Producto no encontrado' });

    // Si no viene orden, poner al final
    let ordenFinal = orden;
    if (ordenFinal === undefined) {
      const [[{ maxOrden }]] = await db.execute(
        'SELECT COALESCE(MAX(orden), -1) AS maxOrden FROM product_images WHERE product_id = ?',
        [req.params.id]
      );
      ordenFinal = maxOrden + 1;
    }

    const [result] = await db.execute(
      'INSERT INTO product_images (product_id, url, orden) VALUES (?, ?, ?)',
      [req.params.id, url, ordenFinal]
    );

    // Si es la primera imagen (orden 0), actualizar también el campo imagen principal
    if (ordenFinal === 0) {
      await db.execute(
        'UPDATE products SET imagen = ?, updatedAt = NOW() WHERE id = ?',
        [url, req.params.id]
      );
    }

    console.log(`✅ Imagen agregada al producto ID ${sanitizeLog(req.params.id)} por ${sanitizeLog(req.user.usuario)}`);
    res.json({ message: 'Imagen agregada correctamente', id: result.insertId, url, orden: ordenFinal });
  } catch (err) {
    console.error('Error agregando imagen:', err);
    res.status(500).json({ error: 'Error agregando imagen' });
  }
});

// ================================
// 🖼️ DELETE /api/admin/products/images/:imageId
// Eliminar una imagen
// ================================

router.delete('/images/:imageId', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();

    const [exists] = await db.execute(
      'SELECT id, product_id, orden FROM product_images WHERE id = ?',
      [req.params.imageId]
    );
    if (exists.length === 0)
      return res.status(404).json({ error: 'Imagen no encontrada' });

    const { product_id, orden } = exists[0];
    await db.execute('DELETE FROM product_images WHERE id = ?', [req.params.imageId]);

    // Si era la imagen principal (orden 0), actualizar products.imagen con la siguiente
    if (orden === 0) {
      const [[next]] = await db.execute(
        'SELECT url FROM product_images WHERE product_id = ? ORDER BY orden ASC LIMIT 1',
        [product_id]
      );
      await db.execute(
        'UPDATE products SET imagen = ?, updatedAt = NOW() WHERE id = ?',
        [next?.url || null, product_id]
      );
    }

    console.log(`🗑️ Imagen ${sanitizeLog(req.params.imageId)} eliminada por ${sanitizeLog(req.user.usuario)}`);
    res.json({ message: 'Imagen eliminada correctamente' });
  } catch (err) {
    console.error('Error eliminando imagen:', err);
    res.status(500).json({ error: 'Error eliminando imagen' });
  }
});

// ================================
// 🖼️ PATCH /api/admin/products/images/reorder
// Reordenar imágenes de un producto
// Body: { product_id, images: [{ id, orden }] }
// ================================

router.patch('/images/reorder', authMiddleware, adminOnly, async (req, res) => {
  const { product_id, images } = req.body;
  if (!product_id || !Array.isArray(images))
    return res.status(400).json({ error: 'product_id e images[] requeridos' });

  try {
    const db = await getDB();

    for (const img of images) {
      await db.execute(
        'UPDATE product_images SET orden = ? WHERE id = ? AND product_id = ?',
        [img.orden, img.id, product_id]
      );
    }

    // Actualizar imagen principal con la de orden 0
    const [[first]] = await db.execute(
      'SELECT url FROM product_images WHERE product_id = ? ORDER BY orden ASC LIMIT 1',
      [product_id]
    );
    if (first) {
      await db.execute(
        'UPDATE products SET imagen = ?, updatedAt = NOW() WHERE id = ?',
        [first.url, product_id]
      );
    }

    res.json({ message: 'Imágenes reordenadas correctamente' });
  } catch (err) {
    console.error('Error reordenando imágenes:', err);
    res.status(500).json({ error: 'Error reordenando imágenes' });
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

    // Si viene imagen, registrarla también en product_images como orden 0
    if (imagen) {
      await db.execute(
        'INSERT INTO product_images (product_id, url, orden) VALUES (?, ?, 0)',
        [productId, imagen]
      );
    }

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

    // Sincronizar imagen principal en product_images (orden 0)
    if (imagen) {
      const [[first]] = await db.execute(
        'SELECT id FROM product_images WHERE product_id = ? AND orden = 0',
        [req.params.id]
      );
      if (first) {
        await db.execute(
          'UPDATE product_images SET url = ? WHERE id = ?',
          [imagen, first.id]
        );
      } else {
        await db.execute(
          'INSERT INTO product_images (product_id, url, orden) VALUES (?, ?, 0)',
          [req.params.id, imagen]
        );
      }
    }

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

    await db.execute('DELETE FROM product_images WHERE product_id = ?', [req.params.id]);
    await db.execute('DELETE FROM inventory WHERE product_id = ?', [req.params.id]);
    await db.execute('DELETE FROM products WHERE id = ?', [req.params.id]);

    console.log(`🗑️ Producto eliminado permanentemente: ${sanitizeLog(exists[0].nombre)} por ${sanitizeLog(req.user.usuario)}`);
    res.json({ message: 'Producto eliminado permanentemente' });
  } catch (err) {
    res.status(500).json({ error: 'Error eliminando producto permanentemente' });
  }
});

module.exports = router;