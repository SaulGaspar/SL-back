const express = require('express');
const router  = express.Router();
const { getDB } = require('../../config/db');

// ── Middleware auth ──
router.use((req, res, next) => {
  const key = req.headers['x-alexa-key'];
  if (process.env.ALEXA_INTERNAL_KEY && key !== process.env.ALEXA_INTERNAL_KEY) {
    return res.status(401).json({ error: 'No autorizado' });
  }
  next();
});

// ─────────────────────────────────────────────
// GET /api/alexa/products
// Devuelve las categorías únicas que existen en la BD
// ─────────────────────────────────────────────
router.get('/products', async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT DISTINCT TRIM(categoria) AS categoria
      FROM products
      WHERE activo = 1
        AND categoria IS NOT NULL
        AND categoria != ''
      ORDER BY categoria
    `);
    res.json({ categories: rows.map(r => r.categoria) });
  } catch (err) {
    console.error('/products error:', err.message);
    res.status(500).json({ error: 'Error obteniendo categorías' });
  }
});

// ─────────────────────────────────────────────
// GET /api/alexa/products/category?name=Calzado
// Devuelve nombre, precio, tallas y colores de cada producto
// ─────────────────────────────────────────────
router.get('/products/category', async (req, res) => {
  try {
    const { name } = req.query;
    if (!name) return res.status(400).json({ error: 'Categoría requerida' });

    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT nombre, precio, talla, colores
      FROM products
      WHERE activo = 1
        AND LOWER(TRIM(categoria)) = LOWER(TRIM(?))
      ORDER BY nombre
      LIMIT 30
    `, [name]);

    res.json({
      category: name,
      // Devuelve objetos completos para que Gemini tenga precio/talla/color por producto
      products: rows.map(r => ({
        nombre:  r.nombre,
        precio:  r.precio,
        tallas:  r.talla   ? r.talla.split(',').map(t => t.trim()).filter(Boolean)   : [],
        colores: r.colores ? r.colores.split(',').map(c => c.trim()).filter(Boolean) : [],
      })),
    });
  } catch (err) {
    console.error('/products/category error:', err.message);
    res.status(500).json({ error: 'Error obteniendo productos' });
  }
});

// ─────────────────────────────────────────────
// GET /api/alexa/stock?product=Tenis+Court+Pro&size=40&color=negro
// Busca por nombre parcial del producto
// ─────────────────────────────────────────────
router.get('/stock', async (req, res) => {
  try {
    const { product, size, color } = req.query;
    if (!product) return res.status(400).json({ error: 'Parámetro product requerido' });

    const db = await getDB();

    let sql = `
      SELECT nombre, precio, talla, colores, stock
      FROM products
      WHERE activo = 1
        AND LOWER(nombre) LIKE LOWER(?)
    `;
    const params = [`%${product}%`];

    if (size) {
      sql += ' AND talla LIKE ?';
      params.push(`%${size}%`);
    }
    if (color) {
      sql += ' AND LOWER(colores) LIKE ?';
      params.push(`%${color.toLowerCase()}%`);
    }

    const [rows] = await db.execute(sql, params);

    const coloresSet = new Set();
    const tallasSet  = new Set();
    let precioMin    = null;
    let hayStock     = false;

    rows.forEach(r => {
      if (r.stock > 0) hayStock = true;
      if (r.colores) r.colores.split(',').forEach(c => { const t = c.trim(); if (t) coloresSet.add(t); });
      if (r.talla)   r.talla.split(',').forEach(t   => { const s = t.trim(); if (s) tallasSet.add(s);  });
      const p = parseFloat(r.precio);
      if (!isNaN(p) && (precioMin === null || p < precioMin)) precioMin = p;
    });

    res.json({
      available: hayStock,
      colors:    [...coloresSet],
      sizes:     [...tallasSet],
      priceFrom: precioMin,
      count:     rows.length,
    });
  } catch (err) {
    console.error('/stock error:', err.message);
    res.status(500).json({ error: 'Error consultando stock' });
  }
});

// ─────────────────────────────────────────────
// GET /api/alexa/branches
// ─────────────────────────────────────────────
router.get('/branches', async (req, res) => {
  try {
    const { id, name } = req.query;
    const db = await getDB();

    if (id) {
      const [rows] = await db.execute(
        'SELECT id, nombre, direccion, telefono FROM branches WHERE id = ? AND activo = 1',
        [id]
      );
      if (!rows.length) return res.status(404).json({ error: 'Sucursal no encontrada' });
      const b = rows[0];
      return res.json({ branch: { name: b.nombre, address: b.direccion, phone: b.telefono, schedule: 'lunes a sábado de 9 AM a 8 PM' } });
    }

    if (name) {
      const [rows] = await db.execute(
        'SELECT id, nombre, direccion, telefono FROM branches WHERE LOWER(nombre) LIKE ? AND activo = 1 LIMIT 1',
        [`%${name.toLowerCase()}%`]
      );
      if (!rows.length) return res.status(404).json({ error: 'Sucursal no encontrada' });
      const b = rows[0];
      return res.json({ branch: { name: b.nombre, address: b.direccion, phone: b.telefono, schedule: 'lunes a sábado de 9 AM a 8 PM' } });
    }

    const [rows] = await db.execute(
      'SELECT id, nombre, direccion, telefono FROM branches WHERE activo = 1 ORDER BY nombre'
    );
    res.json({
      branches: rows.map(b => ({
        id: b.id, name: b.nombre, address: b.direccion,
        phone: b.telefono, schedule: 'lunes a sábado de 9 AM a 8 PM',
      }))
    });
  } catch (err) {
    console.error('/branches error:', err.message);
    res.status(500).json({ error: 'Error obteniendo sucursales' });
  }
});

// ─────────────────────────────────────────────
// GET /api/alexa/promotions
// ─────────────────────────────────────────────
router.get('/promotions', async (req, res) => {
  try {
    const db = await getDB();
    const [tables] = await db.execute(`
      SELECT TABLE_NAME FROM information_schema.TABLES
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'promotions'
    `);
    if (!tables.length) return res.json({ promotions: [] });

    const now = new Date();
    const [rows] = await db.execute(`
      SELECT description FROM promotions
      WHERE active = 1 AND start_date <= ? AND end_date >= ?
      ORDER BY RAND() LIMIT 5
    `, [now, now]);
    res.json({ promotions: rows });
  } catch (err) {
    console.error('/promotions error:', err.message);
    res.status(500).json({ error: 'Error obteniendo promociones' });
  }
});

// ─────────────────────────────────────────────
// GET /api/alexa/orders/:id
// ─────────────────────────────────────────────
router.get('/orders/:id', async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT o.id, o.status, b.nombre AS sucursal_nombre
      FROM orders o
      LEFT JOIN branches b ON b.id = o.sucursal
      WHERE o.id = ? LIMIT 1
    `, [req.params.id]);

    if (!rows.length) return res.status(404).json({ error: 'Pedido no encontrado' });

    const o = rows[0];
    const statusMap = {
      pendiente: 'pendiente de confirmación',
      preparando: 'en preparación',
      en_camino: 'en camino',
      entregado: 'entregado',
      cancelado: 'cancelado',
    };
    res.json({ order: { id: o.id, status: statusMap[o.status] || o.status, branch: o.sucursal_nombre || null } });
  } catch (err) {
    console.error('/orders error:', err.message);
    res.status(500).json({ error: 'Error consultando pedido' });
  }
});

module.exports = router;