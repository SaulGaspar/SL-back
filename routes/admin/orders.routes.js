const express = require('express');
const router = express.Router();

const { getDB } = require('../../config/db');
const { authMiddleware, adminOnly } = require('../../middlewares/auth');

const STATUS_VALIDOS = ['pendiente', 'procesando', 'enviado', 'entregado', 'cancelado'];

// ================================
// 📊 GET /api/admin/orders/stats/summary
// (debe ir ANTES de /:id para no colisionar)
// ================================

router.get('/stats/summary', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();

    const [stats] = await db.execute(`
      SELECT 
        COUNT(*) AS total_ordenes,
        COALESCE(SUM(total), 0) AS ingresos_totales,
        COALESCE(AVG(total), 0) AS ticket_promedio,
        SUM(CASE WHEN status = 'pendiente'  THEN 1 ELSE 0 END) AS pendientes,
        SUM(CASE WHEN status = 'procesando' THEN 1 ELSE 0 END) AS procesando,
        SUM(CASE WHEN status = 'enviado'    THEN 1 ELSE 0 END) AS enviado,
        SUM(CASE WHEN status = 'entregado'  THEN 1 ELSE 0 END) AS entregadas,
        SUM(CASE WHEN status = 'cancelado'  THEN 1 ELSE 0 END) AS canceladas
      FROM orders
    `);

    const [porSucursal] = await db.execute(`
      SELECT o.sucursal, b.nombre AS nombre_sucursal, COUNT(*) AS ordenes, COALESCE(SUM(o.total), 0) AS ingresos
      FROM orders o LEFT JOIN branches b ON b.id = o.sucursal
      GROUP BY o.sucursal, b.nombre ORDER BY ingresos DESC
    `);

    const [ventasPorDia] = await db.execute(`
      SELECT DATE(fecha) AS dia, COUNT(*) AS ordenes, COALESCE(SUM(total), 0) AS ingresos
      FROM orders WHERE fecha >= DATE_SUB(NOW(), INTERVAL 30 DAY)
      GROUP BY dia ORDER BY dia
    `);

    res.json({ resumen: stats[0], porSucursal, ventasPorDia });
  } catch (err) {
    console.error('Error obteniendo estadísticas de órdenes:', err.message);
    res.status(500).json({ error: 'Error obteniendo estadísticas', detalle: err.message });
  }
});

// ================================
// 📋 GET /api/admin/orders
// ================================

router.get('/', authMiddleware, adminOnly, async (req, res) => {
  const { status, sucursal, from, to, user_id, limit } = req.query;

  try {
    const db = await getDB();

    let sql = `
      SELECT o.id, o.user_id, o.total, o.fecha, o.status, o.sucursal,
             u.nombre, u.apellidoP, u.usuario, u.correo
      FROM orders o
      LEFT JOIN users u ON u.id = o.user_id
      WHERE 1=1
    `;

    const params = [];

    if (status && status !== 'all') { sql += ' AND o.status = ?';    params.push(status); }
    if (sucursal && sucursal !== 'all') { sql += ' AND o.sucursal = ?'; params.push(sucursal); }
    if (from)    { sql += ' AND o.fecha >= ?'; params.push(from); }
    if (to)      { sql += ' AND o.fecha <= ?'; params.push(to); }
    if (user_id) { sql += ' AND o.user_id = ?'; params.push(user_id); }

    sql += ' ORDER BY o.fecha DESC';

    const limitNum = parseInt(limit);
    if (limitNum > 0) sql += ` LIMIT ${limitNum}`;

    const [rows] = await db.execute(sql, params);
    res.json(rows);
  } catch (err) {
    console.error('Error obteniendo órdenes:', err.message);
    res.status(500).json({ error: 'Error obteniendo órdenes', detalle: err.message });
  }
});

// ================================
// 📄 GET /api/admin/orders/:id
// ================================

router.get('/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();

    const [order] = await db.execute(`
      SELECT o.id, o.user_id, o.total, o.fecha, o.status, o.sucursal,
             u.nombre, u.apellidoP, u.apellidoM, u.usuario, u.correo, u.telefono
      FROM orders o LEFT JOIN users u ON u.id = o.user_id WHERE o.id = ?
    `, [req.params.id]);

    if (order.length === 0) return res.status(404).json({ error: 'Orden no encontrada' });

    let items = [];
    try {
      const [itemRows] = await db.execute(`
        SELECT oi.*, p.nombre, p.imagen, p.categoria, p.marca
        FROM order_items oi JOIN products p ON p.id = oi.product_id WHERE oi.order_id = ?
      `, [req.params.id]);
      items = itemRows;
    } catch (e) {
      console.warn('Tabla order_items no disponible:', e.message);
    }

    res.json({ order: order[0], items });
  } catch (err) {
    console.error('Error obteniendo detalle de orden:', err.message);
    res.status(500).json({ error: 'Error obteniendo orden', detalle: err.message });
  }
});

// ================================
// 🔄 PATCH /api/admin/orders/:id/status
// ================================

router.patch('/:id/status', authMiddleware, adminOnly, async (req, res) => {
  const { status } = req.body;

  if (!status || !STATUS_VALIDOS.includes(status)) {
    return res.status(400).json({ error: 'Status inválido. Valores permitidos: ' + STATUS_VALIDOS.join(', ') });
  }

  try {
    const db = await getDB();
    const [exists] = await db.execute('SELECT id FROM orders WHERE id = ?', [req.params.id]);
    if (exists.length === 0) return res.status(404).json({ error: 'Orden no encontrada' });

    await db.execute('UPDATE orders SET status = ? WHERE id = ?', [status, req.params.id]);

    console.log(`✅ Status de orden actualizado: Orden #${req.params.id} → '${status}' por admin ${req.user.usuario}`);
    res.json({ message: 'Status actualizado correctamente' });
  } catch (err) {
    console.error('Error actualizando status de orden:', err.message);
    res.status(500).json({ error: 'Error actualizando status', detalle: err.message });
  }
});

module.exports = router;
