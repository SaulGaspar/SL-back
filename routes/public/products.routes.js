const express = require('express');
const router = express.Router();

const { getDB } = require('../../config/db');

// ================================
// GET /api/products
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
// GET /api/categories
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
// GET /api/marcas
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

module.exports = router;
