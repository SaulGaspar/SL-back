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
// Mapa: id del slot Alexa → categoria real en DB
// ─────────────────────────────────────────────
const CATEGORIA_MAP = {
  calzado:      'Calzado',
  ropa:         'Ropa',
  accesorios:   'Accesorio',
  accesorio:    'Accesorio',
  balones:      'Balon',
  balon:        'Balon',
  equipamiento: 'Equipamiento'
};

// Mapa: id del slot producto Alexa → categoria real en DB
const PRODUCTO_CATEGORIA_MAP = {
  tenis:     'Calzado',
  playeras:  'Ropa',
  shorts:    'Ropa',
  leggings:  'Ropa',
  sudadera:  'Ropa',
  balon:     'Balon',
  mochila:   'Accesorio',
  gorra:     'Accesorio'
};

function resolverCategoria(input) {
  if (!input) return null;
  const lower = input.toLowerCase().trim();
  return CATEGORIA_MAP[lower] || null;
}

function resolverCategoriaDesdeProducto(input) {
  if (!input) return null;
  const lower = input.toLowerCase().trim();
  return PRODUCTO_CATEGORIA_MAP[lower] || null;
}

// ─────────────────────────────────────────────
// GET /api/alexa/products
// ─────────────────────────────────────────────
router.get('/products', async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT DISTINCT categoria
      FROM products
      WHERE activo = 1
        AND categoria IS NOT NULL
        AND categoria != ''
      ORDER BY categoria
    `);

    // Devuelve solo los nombres únicos sin duplicados
    const categorias = ['Calzado', 'Ropa', 'Accesorio', 'Balon', 'Equipamiento'];
    const fromDB = rows.map(r => r.categoria);
    const categories = categorias.filter(c => fromDB.includes(c));

    res.json({ categories });
  } catch (err) {
    console.error('Alexa /products error:', err.message);
    res.status(500).json({ error: 'Error obteniendo productos' });
  }
});

// ─────────────────────────────────────────────
// GET /api/alexa/products/category?name=calzado
// ─────────────────────────────────────────────
router.get('/products/category', async (req, res) => {
  try {
    const { name } = req.query;

    if (!name) {
      return res.status(400).json({ error: 'Categoría requerida' });
    }

    // Resuelve el nombre del slot al nombre real en DB
    const categoriaDB = resolverCategoria(name) || name;

    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT nombre
      FROM products
      WHERE activo = 1
        AND LOWER(categoria) = LOWER(?)
      ORDER BY nombre
      LIMIT 20
    `, [categoriaDB]);

    res.json({
      category: name,
      products: rows.map(r => r.nombre)
    });
  } catch (err) {
    console.error('Alexa /products/category error:', err.message);
    res.status(500).json({ error: 'Error obteniendo productos' });
  }
});

// ─────────────────────────────────────────────
// GET /api/alexa/stock?product=tenis&size=27&color=negro
// Devuelve available + colors[] + sizes[]
// ─────────────────────────────────────────────
router.get('/stock', async (req, res) => {
  try {
    const { product, size, color } = req.query;

    if (!product) {
      return res.status(400).json({ error: 'Parámetro product requerido' });
    }

    const db = await getDB();

    // Intenta resolver primero como categoría, luego como producto
    const categoriaDB = resolverCategoria(product)
                     || resolverCategoriaDesdeProducto(product);

    let sql, params;

    if (categoriaDB) {
      // Busca por categoría (cuando el slot es "tenis", "playeras", etc.)
      sql = `
        SELECT v.stock, p.colores, p.talla
        FROM v_inventario_completo v
        JOIN products p ON p.id = v.product_id
        WHERE p.activo = 1
          AND LOWER(p.categoria) = LOWER(?)
          AND v.stock > 0
      `;
      params = [categoriaDB];
    } else {
      // Busca por nombre de producto exacto o parcial
      sql = `
        SELECT v.stock, p.colores, p.talla
        FROM v_inventario_completo v
        JOIN products p ON p.id = v.product_id
        WHERE p.activo = 1
          AND LOWER(p.nombre) LIKE LOWER(?)
          AND v.stock > 0
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

    // Extrae colores y tallas únicos
    const coloresSet = new Set();
    const tallasSet  = new Set();

    rows.forEach(r => {
      if (r.colores) {
        r.colores.split(',').forEach(c => {
          const t = c.trim();
          if (t) coloresSet.add(t);
        });
      }
      if (r.talla) {
        r.talla.split(',').forEach(t => {
          const trimmed = t.trim();
          if (trimmed) tallasSet.add(trimmed);
        });
      }
    });

    res.json({
      available: rows.length > 0,
      colors:    [...coloresSet],
      sizes:     [...tallasSet]
    });
  } catch (err) {
    console.error('Alexa /stock error:', err.message);
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
      if (rows.length === 0)
        return res.status(404).json({ error: 'Sucursal no encontrada' });

      const b = rows[0];
      return res.json({
        branch: {
          name:     b.nombre,
          address:  b.direccion,
          phone:    b.telefono,
          schedule: 'lunes a sábado de nueve de la mañana a ocho de la noche'
        }
      });
    }

    if (name) {
      const [rows] = await db.execute(
        'SELECT id, nombre, direccion, telefono FROM branches WHERE LOWER(nombre) LIKE ? AND activo = 1 LIMIT 1',
        [`%${name.toLowerCase()}%`]
      );
      if (rows.length === 0)
        return res.status(404).json({ error: 'Sucursal no encontrada' });

      const b = rows[0];
      return res.json({
        branch: {
          name:     b.nombre,
          address:  b.direccion,
          phone:    b.telefono,
          schedule: 'lunes a sábado de nueve de la mañana a ocho de la noche'
        }
      });
    }

    const [rows] = await db.execute(
      'SELECT id, nombre, direccion, telefono FROM branches WHERE activo = 1 ORDER BY nombre'
    );
    res.json({
      branches: rows.map(b => ({
        id:       b.id,
        name:     b.nombre,
        address:  b.direccion,
        phone:    b.telefono,
        schedule: 'lunes a sábado de nueve de la mañana a ocho de la noche'
      }))
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
      SELECT TABLE_NAME
      FROM information_schema.TABLES
      WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'promotions'
    `);

    if (tables.length === 0) {
      return res.json({ promotions: [] });
    }

    const now = new Date();
    const [rows] = await db.execute(`
      SELECT description
      FROM promotions
      WHERE active = 1
        AND start_date <= ?
        AND end_date   >= ?
      ORDER BY RAND()
      LIMIT 5
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
      SELECT o.id, o.status, o.fecha, o.total,
             b.nombre AS sucursal_nombre
      FROM orders o
      LEFT JOIN branches b ON b.id = o.sucursal
      WHERE o.id = ?
      LIMIT 1
    `, [req.params.id]);

    if (rows.length === 0)
      return res.status(404).json({ error: 'Pedido no encontrado' });

    const o = rows[0];

    const statusMap = {
      pendiente:  'pendiente de confirmación',
      preparando: 'en preparación',
      en_camino:  'en camino',
      entregado:  'entregado',
      cancelado:  'cancelado'
    };

    res.json({
      order: {
        id:            o.id,
        status:        statusMap[o.status] || o.status,
        branch:        o.sucursal_nombre || null,
        estimatedDate: null
      }
    });
  } catch (err) {
    console.error('Alexa /orders error:', err.message);
    res.status(500).json({ error: 'Error consultando pedido' });
  }
});

module.exports = router;