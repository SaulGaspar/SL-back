const express = require('express');
const router  = express.Router();
const { getDB }                     = require('../../config/db');
const { authMiddleware, adminOnly } = require('../../middlewares/auth');

// 📊 GET /api/admin/reports/summary
router.get('/summary', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const { from, to, branch } = req.query;

    let where = 'WHERE 1=1';
    const p = [];
    if (from)             { where += ' AND DATE(o.fecha) >= ?'; p.push(from); }
    if (to)               { where += ' AND DATE(o.fecha) <= ?'; p.push(to); }
    if (branch && branch !== 'all') { where += ' AND o.sucursal = ?'; p.push(branch); }

    // Totales del período
    const [[cur]] = await db.execute(`
      SELECT
        COUNT(o.id)                                                        AS total_pedidos,
        COALESCE(SUM(CASE WHEN o.status != 'cancelado' THEN o.total END), 0) AS ingresos,
        COALESCE(AVG(CASE WHEN o.status != 'cancelado' THEN o.total END), 0) AS ticket_promedio,
        COUNT(DISTINCT o.user_id)                                          AS clientes_unicos,
        SUM(CASE WHEN o.status = 'cancelado' THEN 1 ELSE 0 END)           AS cancelados,
        SUM(CASE WHEN o.status = 'entregado' THEN 1 ELSE 0 END)           AS entregados,
        SUM(CASE WHEN o.status = 'pendiente' THEN 1 ELSE 0 END)           AS pendientes
      FROM orders o ${where}
    `, p);

    let prev = { ingresos: 0, total_pedidos: 0, clientes_unicos: 0 };
    if (from && to) {
      const days = Math.ceil((new Date(to) - new Date(from)) / 86400000);
      const prevFrom = new Date(new Date(from) - days * 86400000).toISOString().slice(0,10);
      const prevTo   = new Date(new Date(from) - 86400000).toISOString().slice(0,10);
      const [[pp]] = await db.execute(`
        SELECT
          COUNT(o.id) AS total_pedidos,
          COALESCE(SUM(CASE WHEN o.status != 'cancelado' THEN o.total END), 0) AS ingresos,
          COUNT(DISTINCT o.user_id) AS clientes_unicos
        FROM orders o
        WHERE DATE(o.fecha) >= ? AND DATE(o.fecha) <= ?
      `, [prevFrom, prevTo]);
      prev = pp;
    }

    res.json({ current: cur, previous: prev });
  } catch (err) {
    console.error('Error summary:', err);
    res.status(500).json({ error: err.message });
  }
});

// 📈 GET /api/admin/reports/timeline
router.get('/timeline', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const { from, to, branch } = req.query;

    let where = "WHERE o.status != 'cancelado'";
    const p = [];
    if (from)                        { where += ' AND DATE(o.fecha) >= ?'; p.push(from); }
    if (to)                          { where += ' AND DATE(o.fecha) <= ?'; p.push(to); }
    if (branch && branch !== 'all')  { where += ' AND o.sucursal = ?'; p.push(branch); }

    const [rows] = await db.execute(`
      SELECT
        DATE(o.fecha)    AS dia,
        COUNT(o.id)      AS pedidos,
        SUM(o.total)     AS ingresos,
        AVG(o.total)     AS ticket
      FROM orders o ${where}
      GROUP BY DATE(o.fecha)
      ORDER BY dia ASC
    `, p);

    res.json(rows);
  } catch (err) {
    console.error('Error timeline:', err);
    res.status(500).json({ error: err.message });
  }
});

// 🏪 GET /api/admin/reports/by-branch
router.get('/by-branch', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const { from, to } = req.query;

    let where = "WHERE o.status != 'cancelado'";
    const p = [];
    if (from) { where += ' AND DATE(o.fecha) >= ?'; p.push(from); }
    if (to)   { where += ' AND DATE(o.fecha) <= ?'; p.push(to); }

    const [rows] = await db.execute(`
      SELECT
        COALESCE(o.sucursal, 'Sin asignar')   AS sucursal,
        COUNT(o.id)                            AS pedidos,
        COALESCE(SUM(o.total), 0)             AS ingresos,
        COALESCE(AVG(o.total), 0)             AS ticket_promedio,
        COUNT(DISTINCT o.user_id)              AS clientes_unicos,
        SUM(CASE WHEN o.status='cancelado' THEN 1 ELSE 0 END) AS cancelados
      FROM orders o ${where}
      GROUP BY o.sucursal
      ORDER BY ingresos DESC
    `, p);

    res.json(rows);
  } catch (err) {
    console.error('Error by-branch:', err);
    res.status(500).json({ error: err.message });
  }
});

// 🛍️ GET /api/admin/reports/top-products
router.get('/top-products', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const { from, to, branch, limit = 10 } = req.query;

    let where = "WHERE o.status != 'cancelado'";
    const p = [];
    if (from)                        { where += ' AND DATE(o.fecha) >= ?'; p.push(from); }
    if (to)                          { where += ' AND DATE(o.fecha) <= ?'; p.push(to); }
    if (branch && branch !== 'all')  { where += ' AND o.sucursal = ?'; p.push(branch); }

    const [rows] = await db.execute(`
      SELECT
        p.id, p.nombre, p.marca, p.categoria, p.precio, p.imagen,
        SUM(oi.cantidad)                  AS vendidos,
        SUM(oi.cantidad * oi.precio)      AS ingresos,
        COUNT(DISTINCT o.id)              AS num_pedidos
      FROM order_items oi
      JOIN orders  o ON o.id  = oi.order_id
      JOIN products p ON p.id = oi.product_id
      ${where}
      GROUP BY p.id
      ORDER BY vendidos DESC
      LIMIT ?
    `, [...p, Number(limit)]);

    res.json(rows);
  } catch (err) {
    console.error('Error top-products:', err);
    res.status(500).json({ error: err.message });
  }
});

// 🗂️ GET /api/admin/reports/by-category
router.get('/by-category', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const { from, to, branch } = req.query;

    let where = "WHERE o.status != 'cancelado'";
    const p = [];
    if (from)                        { where += ' AND DATE(o.fecha) >= ?'; p.push(from); }
    if (to)                          { where += ' AND DATE(o.fecha) <= ?'; p.push(to); }
    if (branch && branch !== 'all')  { where += ' AND o.sucursal = ?'; p.push(branch); }

    const [rows] = await db.execute(`
      SELECT
        COALESCE(p.categoria, 'Sin categoría') AS categoria,
        SUM(oi.cantidad)                         AS vendidos,
        SUM(oi.cantidad * oi.precio)             AS ingresos,
        COUNT(DISTINCT p.id)                     AS productos_distintos
      FROM order_items oi
      JOIN orders   o ON o.id  = oi.order_id
      JOIN products p ON p.id = oi.product_id
      ${where}
      GROUP BY p.categoria
      ORDER BY ingresos DESC
    `, p);

    res.json(rows);
  } catch (err) {
    console.error('Error by-category:', err);
    res.status(500).json({ error: err.message });
  }
});

// 🏪 GET /api/admin/reports/branch-detail/:id
router.get('/branch-detail/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const { id } = req.params;

    const [[branch]] = await db.execute(`
      SELECT b.*,
        COUNT(DISTINCT i.product_id)  AS productos,
        COALESCE(SUM(i.stock), 0)    AS stock_total,
        COALESCE(SUM(i.stock * p.precio), 0) AS valor_inventario,
        SUM(CASE WHEN i.stock <= i.min_stock AND i.stock > 0 THEN 1 ELSE 0 END) AS bajo_stock,
        SUM(CASE WHEN i.stock = 0 THEN 1 ELSE 0 END) AS sin_stock
      FROM branches b
      LEFT JOIN inventory i ON i.branch_id = b.id
      LEFT JOIN products  p ON p.id = i.product_id
      WHERE b.id = ?
      GROUP BY b.id
    `, [id]);

    if (!branch) return res.status(404).json({ error: 'Sucursal no encontrada' });

    const [[sales]] = await db.execute(`
      SELECT
        COUNT(o.id)           AS pedidos_mes,
        COALESCE(SUM(o.total), 0) AS ingresos_mes,
        COALESCE(AVG(o.total), 0) AS ticket_promedio,
        COUNT(DISTINCT o.user_id) AS clientes_unicos
      FROM orders o
      WHERE o.sucursal = ? AND DATE(o.fecha) >= DATE_SUB(NOW(), INTERVAL 30 DAY)
        AND o.status != 'cancelado'
    `, [branch.nombre]).catch(() => [[{ pedidos_mes:0, ingresos_mes:0, ticket_promedio:0, clientes_unicos:0 }]]);

    const [topProds] = await db.execute(`
      SELECT p.nombre, p.categoria, SUM(oi.cantidad) AS vendidos
      FROM order_items oi
      JOIN orders  o ON o.id = oi.order_id
      JOIN products p ON p.id = oi.product_id
      WHERE o.sucursal = ? AND o.status != 'cancelado'
        AND DATE(o.fecha) >= DATE_SUB(NOW(), INTERVAL 30 DAY)
      GROUP BY p.id ORDER BY vendidos DESC LIMIT 5
    `, [branch.nombre]).catch(() => [[]]);

    const [lowStock] = await db.execute(`
      SELECT p.nombre, p.categoria, i.stock, i.min_stock
      FROM inventory i
      JOIN products p ON p.id = i.product_id
      WHERE i.branch_id = ? AND i.stock <= i.min_stock
      ORDER BY i.stock ASC LIMIT 5
    `, [id]);

    res.json({ branch, sales: sales || {}, topProds, lowStock });
  } catch (err) {
    console.error('Error branch-detail:', err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;