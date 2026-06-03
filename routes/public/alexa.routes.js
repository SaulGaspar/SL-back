const express = require('express');
const router = express.Router();
const { getDB } = require('../../config/db');

// ── Middleware de autenticación Alexa (mejorado)
router.use((req, res, next) => {
  const key = req.headers['x-alexa-key'];
  const validKey = process.env.ALEXA_INTERNAL_KEY;

  if (!validKey) {
    console.warn('⚠️ ALEXA_INTERNAL_KEY no está configurada en Vercel');
  }

  if (!key || !validKey || key !== validKey) {
    console.warn(`Intento no autorizado desde IP: ${req.ip}`);
    return res.status(401).json({ error: 'No autorizado' });
  }

  next();
});

// =============================================
// GET /api/alexa/products/category
// =============================================
router.get('/products/category', async (req, res) => {
  try {
    const { name } = req.query;
    if (!name) return res.status(400).json({ error: 'Se requiere ?name=categoría' });

    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT nombre, precio, talla, colores 
      FROM products 
      WHERE activo = 1 
        AND LOWER(TRIM(categoria)) = LOWER(TRIM(?))
      ORDER BY nombre 
      LIMIT 25
    `, [name]);

    res.json({
      category: name,
      products: rows.map(r => ({
        nombre: r.nombre,
        precio: r.precio,
        tallas: r.talla ? r.talla.split(',').map(t => t.trim()).filter(Boolean) : [],
        colores: r.colores ? r.colores.split(',').map(c => c.trim()).filter(Boolean) : [],
      }))
    });
  } catch (err) {
    console.error('Error /products/category:', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// =============================================
// GET /api/alexa/stock
// =============================================
router.get('/stock', async (req, res) => {
  try {
    const { product, size, color } = req.query;
    if (!product) return res.status(400).json({ error: 'Parámetro product es requerido' });

    const db = await getDB();
    let sql = `SELECT nombre, precio, talla, colores, stock FROM products WHERE activo = 1 AND LOWER(nombre) LIKE LOWER(?)`;
    const params = [`%${product}%`];

    if (size) {
      sql += ` AND talla LIKE ?`;
      params.push(`%${size}%`);
    }
    if (color) {
      sql += ` AND LOWER(colores) LIKE ?`;
      params.push(`%${color.toLowerCase()}%`);
    }

    const [rows] = await db.execute(sql, params);

    const colores = new Set();
    const tallas = new Set();
    let precioMin = null;
    let hayStock = false;

    rows.forEach(r => {
      if (r.stock > 0) hayStock = true;
      if (r.colores) r.colores.split(',').forEach(c => colores.add(c.trim()));
      if (r.talla) r.talla.split(',').forEach(t => tallas.add(t.trim()));
      const p = parseFloat(r.precio);
      if (!isNaN(p) && (precioMin === null || p < precioMin)) precioMin = p;
    });

    res.json({
      available: hayStock,
      colors: [...colores],
      sizes: [...tallas],
      priceFrom: precioMin
    });
  } catch (err) {
    console.error('Error /stock:', err.message);
    res.status(500).json({ error: 'Error consultando stock' });
  }
});


// =============================================
// GET /api/alexa/products/all
// Devuelve TODOS los productos activos (sin filtro de categoría)
// =============================================
router.get('/products/all', async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT nombre, precio, talla, colores, stock, categoria
      FROM products 
      WHERE activo = 1
      ORDER BY categoria, nombre
    `);

    res.json({
      products: rows.map(r => ({
        nombre: r.nombre,
        precio: r.precio,
        tallas: r.talla ? r.talla.split(',').map(t => t.trim()).filter(Boolean) : [],
        colores: r.colores ? r.colores.split(',').map(c => c.trim()).filter(Boolean) : [],
        stock: r.stock,
        categoria: r.categoria
      }))
    });
  } catch (err) {
    console.error('Error /products/all:', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// =============================================
// GET /api/alexa/branches
// =============================================
router.get('/branches', async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT nombre, direccion, telefono 
      FROM branches 
      WHERE activo = 1 
      ORDER BY nombre
    `);

    res.json({
      branches: rows.map(b => ({
        name: b.nombre,
        address: b.direccion,
        schedule: 'Lunes a sábado de 9:00 AM a 8:00 PM'
      }))
    });
  } catch (err) {
    console.error('Error /branches:', err.message);
    res.status(500).json({ error: 'Error obteniendo sucursales' });
  }
});

// =============================================
// GET /api/alexa/product/details
// Busca un producto por nombre exacto o parcial
// =============================================
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
      LIMIT 1
    `, [`%${name}%`]);

    if (rows.length === 0) {
      return res.json({ found: false });
    }

    const p = rows[0];
    res.json({
      found: true,
      product: {
        nombre: p.nombre,
        precio: p.precio,
        tallas: p.talla ? p.talla.split(',').map(t => t.trim()).filter(Boolean) : [],
        colores: p.colores ? p.colores.split(',').map(c => c.trim()).filter(Boolean) : [],
        stock: p.stock,
        categoria: p.categoria
      }
    });
  } catch (err) {
    console.error('Error /product/details:', err.message);
    res.status(500).json({ error: 'Error interno' });
  }
});

// =============================================
// GET /api/alexa/promotions
// =============================================
router.get('/promotions', async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT description 
      FROM promotions 
      WHERE active = 1 
        AND start_date <= CURDATE() 
        AND end_date >= CURDATE()
      ORDER BY RAND() LIMIT 5
    `);

    res.json({ promotions: rows });
  } catch (err) {
    console.error('Error /promotions:', err.message);
    res.status(500).json({ error: 'Error obteniendo promociones' });
  }
});

module.exports = router;