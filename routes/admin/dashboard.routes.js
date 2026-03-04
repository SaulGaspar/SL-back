const express = require('express');
const router = express.Router();

const { getDB } = require('../../config/db');
const { authMiddleware, adminOnly } = require('../../middlewares/auth');

// ================================
// 📊 GET /api/admin/dashboard
// ================================

router.get('/', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const { from, to, branch } = req.query;

    const where  = [];
    const params = [];

    if (from)                { where.push('o.fecha >= ?');    params.push(from); }
    if (to)                  { where.push('o.fecha <= ?');    params.push(to); }
    if (branch && branch !== 'all') { where.push('o.sucursal = ?'); params.push(branch); }

    const whereSQL = where.length ? 'WHERE ' + where.join(' AND ') : '';

    const [timeline] = await db.execute(`
      SELECT DATE(o.fecha) AS dia, COALESCE(SUM(o.total), 0) AS total
      FROM orders o ${whereSQL} GROUP BY dia ORDER BY dia
    `, params);

    const [branches] = await db.execute(`
      SELECT COALESCE(b.nombre, CONCAT('Sucursal ', o.sucursal)) AS sucursal,
             COALESCE(SUM(o.total), 0) AS ingresos
      FROM orders o
      LEFT JOIN branches b ON b.id = o.sucursal
      ${whereSQL} GROUP BY o.sucursal, b.nombre ORDER BY ingresos DESC
    `, params);

    let topProducts = [];
    try {
      const [tp] = await db.execute(`
        SELECT p.nombre, p.marca, SUM(oi.cantidad) AS vendidos, SUM(oi.subtotal) AS ingresos
        FROM order_items oi
        JOIN products p ON p.id = oi.product_id
        JOIN orders o ON o.id = oi.order_id
        ${whereSQL} GROUP BY p.nombre, p.marca ORDER BY vendidos DESC LIMIT 10
      `, params);
      topProducts = tp;
    } catch (e) {
      console.warn('order_items no disponible:', e.message);
    }

    res.json({ salesTimeline: timeline, branchRanking: branches, topProducts });
  } catch (err) {
    console.error('Error en dashboard admin:', err.message);
    res.status(500).json({ error: 'Error generando dashboard admin', detalle: err.message });
  }
});

module.exports = router;
