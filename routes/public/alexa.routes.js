const express = require('express');
const router  = express.Router();
const { getDB } = require('../../config/db');

// ── Middleware: valida clave interna desde Alexa Lambda ──
router.use((req, res, next) => {
  const key = req.headers['x-alexa-key'];
  if (process.env.ALEXA_INTERNAL_KEY && key !== process.env.ALEXA_INTERNAL_KEY) {
    return res.status(401).json({ error: 'No autorizado' });
  }
  next();
});

// ─────────────────────────────────────────────
// GET /api/alexa/products
// Devuelve categorías distintas de productos activos
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
    const categories = rows.map(r => r.categoria);
    res.json({ categories });
  } catch (err) {
    console.error('Alexa /products error:', err.message);
    res.status(500).json({ error: 'Error obteniendo productos' });
  }
});

// ─────────────────────────────────────────────
// GET /api/alexa/stock?product=tenis&size=27&color=negro
// Consulta disponibilidad real desde inventory + products
// ─────────────────────────────────────────────
router.get('/stock', async (req, res) => {
  try {
    const { product, size, color } = req.query;

    if (!product) {
      return res.status(400).json({ error: 'Parámetro product requerido' });
    }

    const db = await getDB();

    // Busca en la vista que ya usas en inventory.routes.js
    let sql = `
      SELECT v.stock, v.estado
      FROM v_inventario_completo v
      JOIN products p ON p.id = v.product_id
      WHERE p.activo = 1
        AND LOWER(p.categoria) = LOWER(?)
        AND v.stock > 0
    `;
    const params = [product];

    // talla está en products.talla (campo texto)
    if (size) {
      sql += ' AND p.talla LIKE ?';
      params.push(`%${size}%`);
    }

    // colores está en products.colores (campo texto)
    if (color) {
      sql += ' AND LOWER(p.colores) LIKE ?';
      params.push(`%${color.toLowerCase()}%`);
    }

    sql += ' LIMIT 1';

    const [rows] = await db.execute(sql, params);
    res.json({ available: rows.length > 0 });
  } catch (err) {
    console.error('Alexa /stock error:', err.message);
    res.status(500).json({ error: 'Error consultando stock' });
  }
});

// ─────────────────────────────────────────────
// GET /api/alexa/branches          → todas las activas
// GET /api/alexa/branches?id=1     → una por id numérico
// GET /api/alexa/branches?name=centro → una por nombre
// ─────────────────────────────────────────────
router.get('/branches', async (req, res) => {
  try {
    const { id, name } = req.query;
    const db = await getDB();

    // Sucursal específica por id numérico
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
          // horario no está en tu tabla branches, se devuelve fijo
          schedule: 'lunes a sábado de nueve de la mañana a ocho de la noche'
        }
      });
    }

    // Sucursal específica por nombre parcial (ej: "centro", "juárez")
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

    // Todas las sucursales activas
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
// Si tienes tabla promotions úsala; si no, devuelve vacío
// para que el fallback de la Lambda entre en acción
// ─────────────────────────────────────────────
router.get('/promotions', async (req, res) => {
  try {
    const db = await getDB();

    // Verifica si existe la tabla promotions antes de consultar
    const [tables] = await db.execute(`
      SELECT TABLE_NAME
      FROM information_schema.TABLES
      WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'promotions'
    `);

    if (tables.length === 0) {
      // No tienes tabla promotions aún → devuelve vacío,
      // la Lambda usará sus respuestas de fallback
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

//priductos xd

router.get('/products/category', async (req, res) => {
  try {
    const { name } = req.query;

    if (!name) {
      return res.status(400).json({
        error: 'Categoría requerida'
      });
    }

    const db = await getDB();

    const [rows] = await db.execute(`
      SELECT nombre
      FROM products
      WHERE activo = 1
      AND LOWER(categoria) = LOWER(?)
      ORDER BY nombre
      LIMIT 20
    `, [name]);

    res.json({
      category: name,
      products: rows.map(r => r.nombre)
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: 'Error obteniendo productos'
    });
  }
});



// ─────────────────────────────────────────────
// GET /api/alexa/orders/:id
// Busca por orders.id (numérico)
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

    // Mapea los mismos status que usa tu orders.routes.js
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
        // fecha estimada no está en tu tabla; se omite
        estimatedDate: null
      }
    });
  } catch (err) {
    console.error('Alexa /orders error:', err.message);
    res.status(500).json({ error: 'Error consultando pedido' });
  }
});

module.exports = router;