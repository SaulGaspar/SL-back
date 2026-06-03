const express = require('express');
const router  = express.Router();
const { getDB } = require('../../config/db');

// ── Middleware ──
router.use((req, res, next) => {
  const key = req.headers['x-alexa-key'];
  if (process.env.ALEXA_INTERNAL_KEY && key !== process.env.ALEXA_INTERNAL_KEY) {
    return res.status(401).json({ error: 'No autorizado' });
  }
  next();
});

// ─────────────────────────────────────────────
// NORMALIZACIÓN DE CATEGORÍAS
// Agrupa todas las variantes de nombre que existen en la BD
// bajo un nombre canónico único.
// ─────────────────────────────────────────────
const CATEGORIA_GRUPOS = {
  Calzado: ['calzado', 'calzado deportivo', 'tenis', 'zapatillas'],
  Ropa:    ['ropa', 'ropa deportiva'],
  Accesorio: ['accesorio', 'accesorios'],
  Balon:   ['balon', 'balones'],
  Equipamiento: ['equipamiento'],
};

// Devuelve el nombre canónico para cualquier string que llegue
function normalizarCategoria(input) {
  if (!input) return null;
  const lower = input.toLowerCase().trim();
  for (const [canonical, aliases] of Object.entries(CATEGORIA_GRUPOS)) {
    if (aliases.includes(lower)) return canonical;
  }
  return null;
}

// Genera la cláusula SQL WHERE para una categoría canónica
// (cubre todas las variantes almacenadas en la BD)
function whereCategoria(canonical) {
  const aliases = CATEGORIA_GRUPOS[canonical] || [canonical.toLowerCase()];
  const placeholders = aliases.map(() => 'LOWER(categoria) = ?').join(' OR ');
  return { clause: `(${placeholders})`, values: aliases };
}

// ─────────────────────────────────────────────
// GET /api/alexa/products
// Devuelve las categorías canónicas que tienen productos activos
// ─────────────────────────────────────────────
router.get('/products', async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT DISTINCT LOWER(TRIM(categoria)) AS cat
      FROM products
      WHERE activo = 1
        AND categoria IS NOT NULL
        AND categoria != ''
    `);

    // Mapea cada fila a su nombre canónico y deduplica
    const foundSet = new Set(rows.map(r => normalizarCategoria(r.cat)).filter(Boolean));

    // Devuelve en orden fijo
    const orden = ['Calzado', 'Ropa', 'Accesorio', 'Balon', 'Equipamiento'];
    const categories = orden.filter(c => foundSet.has(c));

    res.json({ categories });
  } catch (err) {
    console.error('Alexa /products error:', err.message);
    res.status(500).json({ error: 'Error obteniendo productos' });
  }
});

// ─────────────────────────────────────────────
// GET /api/alexa/products/category?name=calzado
// Devuelve nombres de productos dinámicamente desde la BD
// ─────────────────────────────────────────────
router.get('/products/category', async (req, res) => {
  try {
    const { name } = req.query;
    if (!name) return res.status(400).json({ error: 'Categoría requerida' });

    const canonical = normalizarCategoria(name);
    if (!canonical) {
      return res.status(400).json({ error: `Categoría desconocida: ${name}` });
    }

    const { clause, values } = whereCategoria(canonical);
    const db = await getDB();
    const [rows] = await db.execute(
      `SELECT nombre FROM products WHERE activo = 1 AND ${clause} ORDER BY nombre LIMIT 20`,
      values
    );

    res.json({
      category: canonical,
      products: rows.map(r => r.nombre),
    });
  } catch (err) {
    console.error('Alexa /products/category error:', err.message);
    res.status(500).json({ error: 'Error obteniendo productos' });
  }
});

// ─────────────────────────────────────────────
// GET /api/alexa/stock?product=tenis&size=40&color=negro
// Busca por nombre de producto (parcial) o por categoría canónica.
// Devuelve available, colors[], sizes[], price (precio mínimo).
// ─────────────────────────────────────────────
router.get('/stock', async (req, res) => {
  try {
    const { product, size, color } = req.query;
    if (!product) return res.status(400).json({ error: 'Parámetro product requerido' });

    const db = await getDB();
    const canonical = normalizarCategoria(product);

    let sql, params;

    if (canonical) {
      // El slot resolvió a una categoría (ej. "tenis" → Calzado)
      const { clause, values } = whereCategoria(canonical);
      sql = `
        SELECT p.nombre, p.colores, p.talla, p.precio, p.stock
        FROM products p
        WHERE p.activo = 1
          AND ${clause}
          AND p.stock > 0
      `;
      params = [...values];
    } else {
      // Busca por nombre parcial del producto
      sql = `
        SELECT p.nombre, p.colores, p.talla, p.precio, p.stock
        FROM products p
        WHERE p.activo = 1
          AND LOWER(p.nombre) LIKE LOWER(?)
          AND p.stock > 0
      `;
      params = [`%${product}%`];
    }

    if (size) {
      sql += ' AND p.talla LIKE ?';
      params.push(`%${size}%`);
    }
    if (color) {
      sql += ' AND LOWER(p.colores) LIKE ?';
      params.push(`%${color.toLowerCase()}%`);
    }

    const [rows] = await db.execute(sql, params);

    // Acumula colores, tallas y precio mínimo
    const coloresSet = new Set();
    const tallasSet  = new Set();
    let precioMin = null;

    rows.forEach(r => {
      if (r.colores) {
        r.colores.split(',').forEach(c => {
          const t = c.trim(); if (t) coloresSet.add(t);
        });
      }
      if (r.talla) {
        r.talla.split(',').forEach(t => {
          const trimmed = t.trim(); if (trimmed) tallasSet.add(trimmed);
        });
      }
      const precio = parseFloat(r.precio);
      if (!isNaN(precio) && (precioMin === null || precio < precioMin)) {
        precioMin = precio;
      }
    });

    res.json({
      available: rows.length > 0,
      colors:    [...coloresSet],
      sizes:     [...tallasSet],
      priceFrom: precioMin,
    });
  } catch (err) {
    console.error('Alexa /stock error:', err.message);
    res.status(500).json({ error: 'Error consultando stock' });
  }
});

// ─────────────────────────────────────────────
// GET /api/alexa/product/detail?name=Tenis+Court+Pro
// Devuelve detalle completo de un producto específico
// ─────────────────────────────────────────────
router.get('/product/detail', async (req, res) => {
  try {
    const { name } = req.query;
    if (!name) return res.status(400).json({ error: 'Nombre requerido' });

    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT nombre, marca, descripcion, precio, categoria, talla, colores, stock
      FROM products
      WHERE activo = 1
        AND LOWER(nombre) LIKE LOWER(?)
      ORDER BY nombre
      LIMIT 5
    `, [`%${name}%`]);

    if (!rows.length) {
      return res.status(404).json({ error: 'Producto no encontrado' });
    }

    // Consolida tallas y colores de todas las variantes
    const coloresSet = new Set();
    const tallasSet  = new Set();
    let precioMin = null;

    rows.forEach(r => {
      if (r.colores) r.colores.split(',').forEach(c => { const t = c.trim(); if (t) coloresSet.add(t); });
      if (r.talla)   r.talla.split(',').forEach(t  => { const s = t.trim(); if (s) tallasSet.add(s); });
      const p = parseFloat(r.precio);
      if (!isNaN(p) && (precioMin === null || p < precioMin)) precioMin = p;
    });

    const base = rows[0];
    res.json({
      product: {
        nombre:    base.nombre,
        marca:     base.marca || null,
        categoria: normalizarCategoria(base.categoria) || base.categoria,
        precio:    precioMin,
        tallas:    [...tallasSet],
        colores:   [...coloresSet],
        disponible: rows.some(r => r.stock > 0),
      }
    });
  } catch (err) {
    console.error('Alexa /product/detail error:', err.message);
    res.status(500).json({ error: 'Error consultando producto' });
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
      return res.json({ branch: { name: b.nombre, address: b.direccion, phone: b.telefono, schedule: 'lunes a sábado de nueve de la mañana a ocho de la noche' } });
    }

    if (name) {
      const [rows] = await db.execute(
        'SELECT id, nombre, direccion, telefono FROM branches WHERE LOWER(nombre) LIKE ? AND activo = 1 LIMIT 1',
        [`%${name.toLowerCase()}%`]
      );
      if (!rows.length) return res.status(404).json({ error: 'Sucursal no encontrada' });
      const b = rows[0];
      return res.json({ branch: { name: b.nombre, address: b.direccion, phone: b.telefono, schedule: 'lunes a sábado de nueve de la mañana a ocho de la noche' } });
    }

    const [rows] = await db.execute(
      'SELECT id, nombre, direccion, telefono FROM branches WHERE activo = 1 ORDER BY nombre'
    );
    res.json({
      branches: rows.map(b => ({ id: b.id, name: b.nombre, address: b.direccion, phone: b.telefono, schedule: 'lunes a sábado de nueve de la mañana a ocho de la noche' }))
    });
  } catch (err) {
    console.error('Alexa /branches error:', err.message);
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
    console.error('Alexa /promotions error:', err.message);
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
      SELECT o.id, o.status, o.fecha, o.total, b.nombre AS sucursal_nombre
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

    res.json({ order: { id: o.id, status: statusMap[o.status] || o.status, branch: o.sucursal_nombre || null, estimatedDate: null } });
  } catch (err) {
    console.error('Alexa /orders error:', err.message);
    res.status(500).json({ error: 'Error consultando pedido' });
  }
});

module.exports = router;