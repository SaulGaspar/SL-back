const express = require('express');
const router = express.Router();
const { getDB } = require('../../config/db');
const autenticarAlexa = (req, res, next) => {
  const key = req.headers['x-alexa-key'];
  const validKey = process.env.ALEXA_INTERNAL_KEY;
  if (!key || !validKey || key !== validKey) {
    console.warn(`Acceso no autorizado desde IP: ${req.ip}`);
    return res.status(401).json({ error: 'No autorizado' });
  }
  next();
};
router.use(autenticarAlexa);
const mapearProducto = (r) => ({
  nombre: r.nombre,
  precio: r.precio,
  tallas: r.talla ? r.talla.split(',').map(t => t.trim()).filter(Boolean) : [],
  colores: r.colores ? r.colores.split(',').map(c => c.trim()).filter(Boolean) : [],
  stock: r.stock ?? null,
  categoria: r.categoria ?? null,
});
router.get('/products/all', async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT nombre, precio, talla, colores, stock, categoria
      FROM products
      WHERE activo = 1
      ORDER BY categoria ASC, nombre ASC
    `);
    res.json({ total: rows.length, products: rows.map(mapearProducto) });
  } catch (err) {
    console.error('GET /products/all:', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});
router.get('/products/category', async (req, res) => {
  try {
    const { name } = req.query;
    if (!name) return res.status(400).json({ error: 'Se requiere ?name=categoría' });
    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT nombre, precio, talla, colores, stock, categoria
      FROM products
      WHERE activo = 1
        AND LOWER(TRIM(categoria)) = LOWER(TRIM(?))
      ORDER BY nombre ASC
      LIMIT 30
    `, [name]);
    res.json({ category: name, total: rows.length, products: rows.map(mapearProducto) });
  } catch (err) {
    console.error('GET /products/category:', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});
router.get('/product/details', async (req, res) => {
  try {
    const { name } = req.query;
    if (!name) return res.status(400).json({ error: 'Se requiere ?name=producto' });
    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT nombre, precio, talla, colores, stock, categoria
      FROM products
      WHERE activo = 1
        AND LOWER(nombre) LIKE LOWER(?)
      ORDER BY CHAR_LENGTH(nombre) ASC
      LIMIT 1
    `, [`%${name}%`]);
    if (!rows.length) return res.json({ found: false });
    res.json({ found: true, product: mapearProducto(rows[0]) });
  } catch (err) {
    console.error('GET /product/details:', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});
router.get('/stock', async (req, res) => {
  try {
    const { product, size, color } = req.query;
    if (!product) return res.status(400).json({ error: 'Se requiere ?product=nombre' });
    const db = await getDB();
    let sql = `
      SELECT nombre, precio, talla, colores, stock
      FROM products
      WHERE activo = 1
        AND LOWER(nombre) LIKE LOWER(?)
    `;
    const params = [`%${product}%`];
    if (size) {
      sql += ` AND FIND_IN_SET(LOWER(?), LOWER(REPLACE(talla, ' ', '')))`;
      params.push(size.toLowerCase());
    }
    if (color) {
      sql += ` AND LOWER(colores) LIKE LOWER(?)`;
      params.push(`%${color}%`);
    }
    const [rows] = await db.execute(sql, params);
    const coloresDisponibles = new Set();
    const tallasDisponibles = new Set();
    let precioMinimo = null;
    let totalStock = 0;
    rows.forEach(r => {
      totalStock += r.stock || 0;
      if (r.colores) r.colores.split(',').forEach(c => coloresDisponibles.add(c.trim()));
      if (r.talla) r.talla.split(',').forEach(t => tallasDisponibles.add(t.trim()));
      const p = parseFloat(r.precio);
      if (!isNaN(p) && (precioMinimo === null || p < precioMinimo)) precioMinimo = p;
    });
    res.json({
      available: totalStock > 0,
      totalStock,
      colors: [...coloresDisponibles],
      sizes: [...tallasDisponibles],
      priceFrom: precioMinimo,
    });
  } catch (err) {
    console.error('GET /stock:', err.message);
    res.status(500).json({ error: 'Error consultando stock' });
  }
});
router.get('/branches', async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT nombre, direccion, telefono, horario
      FROM branches
      WHERE activo = 1
      ORDER BY nombre ASC
    `);
    res.json({
      total: rows.length,
      branches: rows.map(b => ({
        name: b.nombre,
        address: b.direccion,
        phone: b.telefono || null,
        schedule: b.horario || 'Lunes a sábado de 9:00 AM a 8:00 PM',
      })),
    });
  } catch (err) {
    console.error('GET /branches:', err.message);
    res.status(500).json({ error: 'Error obteniendo sucursales' });
  }
});
router.get('/promotions', async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT description, start_date, end_date
      FROM promotions
      WHERE active = 1
        AND start_date <= CURDATE()
        AND end_date >= CURDATE()
      ORDER BY end_date ASC
      LIMIT 5
    `);
    res.json({ total: rows.length, promotions: rows });
  } catch (err) {
    console.error('GET /promotions:', err.message);
    res.status(500).json({ error: 'Error obteniendo promociones' });
  }
});
router.get('/categories', async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT DISTINCT categoria, COUNT(*) AS total
      FROM products
      WHERE activo = 1
        AND categoria IS NOT NULL
      GROUP BY categoria
      ORDER BY categoria ASC
    `);
    res.json({
      total: rows.length,
      categories: rows.map(r => ({ name: r.categoria, count: r.total })),
    });
  } catch (err) {
    console.error('GET /categories:', err.message);
    res.status(500).json({ error: 'Error obteniendo categorías' });
  }
});
module.exports = router;