const express = require('express');
const router = express.Router();

const { getDB } = require('../../config/db');

// ================================
// 📦 GET /api/products
// ================================
router.get('/', async (req, res) => {
  const { q, categoria, marca } = req.query;

  try {
    const db = await getDB();

    let sql = `
      SELECT 
        p.id, p.nombre, p.marca, p.descripcion, p.precio,
        p.categoria, p.imagen, p.talla, p.colores,
        COALESCE(SUM(i.stock), 0) AS stock_total
      FROM products p
      LEFT JOIN inventory i ON i.product_id = p.id
      WHERE p.activo = 1
    `;

    const params = [];

    if (q) {
      sql += ' AND (p.nombre LIKE ? OR p.descripcion LIKE ?)';
      params.push(`%${q}%`, `%${q}%`);
    }
    if (categoria) { sql += ' AND p.categoria = ?'; params.push(categoria); }
    if (marca)     { sql += ' AND p.marca = ?';     params.push(marca); }

    sql += ' GROUP BY p.id ORDER BY p.nombre';

    const [rows] = await db.execute(sql, params);
    res.json(rows);
  } catch (err) {
    console.error('Error obteniendo productos públicos:', err);
    res.status(500).json({ error: 'Error obteniendo productos' });
  }
});

// ================================
// 📂 GET /api/products/categories
// ================================
router.get('/categories', async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT DISTINCT categoria AS nombre FROM products
      WHERE activo = 1 AND categoria IS NOT NULL AND categoria != ''
      ORDER BY categoria
    `);
    res.json(rows.map(r => r.nombre));
  } catch (err) {
    res.status(500).json({ error: 'Error obteniendo categorías' });
  }
});

// ================================
// 🏷️ GET /api/products/marcas
// ================================
router.get('/marcas', async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT DISTINCT marca AS nombre FROM products
      WHERE activo = 1 AND marca IS NOT NULL AND marca != ''
      ORDER BY marca
    `);
    res.json(rows.map(r => r.nombre));
  } catch (err) {
    res.status(500).json({ error: 'Error obteniendo marcas' });
  }
});

// ⚠️ =====================================================================
// 📉 GET /api/products/prediccion-publica — RUTA FIJA, DEBE IR AQUÍ
// ⚠️ ANTES de GET /:id para que Express no lo interprete como parámetro
// =====================================================================
router.get('/prediccion-publica', async (req, res) => {
  try {
    const db = await getDB();
    const DIAS_PERIODO = 30;

    const [rows] = await db.execute(`
      SELECT
        i.product_id,
        i.branch_id,
        i.stock        AS stock_actual,
        p.nombre       AS producto,
        p.categoria,
        b.nombre       AS sucursal,
        COALESCE(
          (
            SELECT SUM(oi.cantidad)
            FROM order_items oi
            JOIN orders o ON o.id = oi.order_id
            WHERE oi.product_id = i.product_id
              AND o.sucursal    = i.branch_id
              AND o.fecha      >= DATE_SUB(NOW(), INTERVAL ${DIAS_PERIODO} DAY)
              AND o.status NOT IN ('cancelado')
          ), 0
        ) AS ventas_periodo
      FROM inventory i
      JOIN products  p ON p.id = i.product_id
      JOIN branches  b ON b.id = i.branch_id
      WHERE p.activo = 1
      ORDER BY i.product_id
    `);

    const resultado = rows.map(row => {
      const r = row.ventas_periodo / DIAS_PERIODO; // tasa diaria (u/día)
      let dias_restantes    = null;
      let fecha_agotamiento = null;
      let alerta            = 'ok';

      if (row.stock_actual === 0) {
        alerta = 'agotado';
      } else if (r <= 0) {
        alerta = 'sin_movimiento';
      } else {
        // ✅ Sin Math.floor — valor decimal para que el frontend calcule horas exactas
        dias_restantes = row.stock_actual / r;

        const fecha = new Date();
        fecha.setDate(fecha.getDate() + Math.floor(dias_restantes));
        fecha_agotamiento = fecha.toISOString().slice(0, 10);

        if      (dias_restantes <= 7)  alerta = 'critico';
        else if (dias_restantes <= 15) alerta = 'bajo';
        else if (dias_restantes <= 30) alerta = 'moderado';
      }

      return {
        product_id:       row.product_id,
        branch_id:        row.branch_id,
        stock_actual:     row.stock_actual,
        ventas_periodo:   Number(row.ventas_periodo),
        tasa_diaria:      parseFloat(r.toFixed(4)),
        dias_restantes,                            // ✅ decimal, ej: 0.208 = 5 horas
        fecha_agotamiento,
        alerta,
      };
    });

    res.json(resultado);
  } catch (err) {
    console.error('Error predicción pública:', err.message);
    res.status(500).json({ error: 'Error calculando predicción' });
  }
});

// ================================
// 🖼️ GET /api/products/:id/images  — público, sin auth
// ⚠️  DESPUÉS de todas las rutas con nombre fijo
// ================================
router.get('/:id/images', async (req, res) => {
  try {
    const db = await getDB();
    const [images] = await db.execute(`
      SELECT id, url, orden
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
// ⚠️ GET /api/products/:id — RUTA DINÁMICA, SIEMPRE AL FINAL
// ================================
router.get('/:id', async (req, res) => {
  try {
    const db = await getDB();
    const [product] = await db.execute(`
      SELECT 
        p.id, p.nombre, p.marca, p.descripcion, p.precio,
        p.categoria, p.imagen, p.talla, p.colores,
        COALESCE(SUM(i.stock), 0) AS stock_total
      FROM products p
      LEFT JOIN inventory i ON i.product_id = p.id
      WHERE p.id = ? AND p.activo = 1
      GROUP BY p.id
    `, [req.params.id]);

    if (!product || product.length === 0) {
      return res.status(404).json({ error: 'Producto no encontrado' });
    }

    const [images] = await db.execute(`
      SELECT id, url, orden
      FROM product_images
      WHERE product_id = ?
      ORDER BY orden ASC
    `, [req.params.id]);

    res.json({ ...product[0], images });
  } catch (err) {
    console.error('Error obteniendo producto:', err);
    res.status(500).json({ error: 'Error obteniendo producto' });
  }
});

module.exports = router;