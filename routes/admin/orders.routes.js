const express = require('express');
const router = express.Router();

const { getDB } = require('../../config/db');
const { authMiddleware, adminOnly } = require('../../middlewares/auth');
const { sanitizeLog } = require('../../helpers/sanitizeLog');

const STATUS_VALIDOS = ['pendiente', 'procesando', 'enviado', 'entregado', 'cancelado'];

// ================================
// 📊 GET /stats/summary
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
    console.error('Error obteniendo estadísticas:', err.message);
    res.status(500).json({ error: 'Error obteniendo estadísticas', detalle: err.message });
  }
});

// ================================
// 📋 GET /mis-pedidos  ← cliente logueado
// ⚠️  ANTES de /:id para que Express no lo confunda con un parámetro
// ================================
router.get('/mis-pedidos', authMiddleware, async (req, res) => {
  try {
    const db = await getDB();

    // Traer todos los sub-pedidos del usuario con su pedido_ref
    const [rows] = await db.execute(`
      SELECT o.id, o.total, o.status, o.fecha, o.sucursal,
             b.nombre AS sucursal_nombre,
             COALESCE(o.pedido_ref, CAST(o.id AS CHAR)) AS pedido_ref
      FROM orders o
      LEFT JOIN branches b ON b.id = o.sucursal
      WHERE o.user_id = ?
      ORDER BY o.fecha DESC
    `, [req.user.id]);

    // Agrupar por pedido_ref → un solo objeto por compra
    const mapaGrupos = {};
    for (const row of rows) {
      const ref = row.pedido_ref;
      if (!mapaGrupos[ref]) {
        mapaGrupos[ref] = {
          id:              row.id,
          pedido_ref:      ref,
          status:          row.status,
          fecha:           row.fecha,
          sucursal:        row.sucursal,
          sucursal_nombre: row.sucursal_nombre,
          total:           0,
          items:           [],
          subIds:          [],
        };
      }
      mapaGrupos[ref].total  += Number(row.total);
      mapaGrupos[ref].subIds.push(row.id);
    }

    // Obtener items de todos los sub-pedidos y unirlos
    for (const grupo of Object.values(mapaGrupos)) {
      for (const subId of grupo.subIds) {
        try {
          const [items] = await db.execute(`
            SELECT oi.cantidad, oi.subtotal,
                   p.nombre, p.imagen, p.categoria, p.marca
            FROM order_items oi
            JOIN products p ON p.id = oi.product_id
            WHERE oi.order_id = ?
          `, [subId]);
          grupo.items.push(...items);
        } catch { /* skip */ }
      }
      delete grupo.subIds; // no exponer internamente
    }

    const pedidos = Object.values(mapaGrupos)
      .sort((a, b) => new Date(b.fecha) - new Date(a.fecha));

    res.json(pedidos);
  } catch (err) {
    console.error('Error obteniendo mis pedidos:', err.message);
    res.status(500).json({ error: 'Error obteniendo pedidos', detalle: err.message });
  }
});

// ================================
// 📋 GET /  (admin)
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
    if (status && status !== 'all')     { sql += ' AND o.status = ?';    params.push(status); }
    if (sucursal && sucursal !== 'all') { sql += ' AND o.sucursal = ?';  params.push(sucursal); }
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
// 📄 GET /:id  (admin)
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
    } catch (e) { console.warn('order_items no disponible:', e.message); }
    res.json({ order: order[0], items });
  } catch (err) {
    console.error('Error obteniendo orden:', err.message);
    res.status(500).json({ error: 'Error obteniendo orden', detalle: err.message });
  }
});

// ================================
// 🔄 PATCH /:id/status  (admin)
// ================================
router.patch('/:id/status', authMiddleware, adminOnly, async (req, res) => {
  const { status } = req.body;
  if (!status || !STATUS_VALIDOS.includes(status))
    return res.status(400).json({ error: 'Status inválido. Valores: ' + STATUS_VALIDOS.join(', ') });
  try {
    const db = await getDB();
    const [exists] = await db.execute('SELECT id FROM orders WHERE id = ?', [req.params.id]);
    if (exists.length === 0) return res.status(404).json({ error: 'Orden no encontrada' });
    await db.execute('UPDATE orders SET status = ? WHERE id = ?', [status, req.params.id]);
    console.log(`✅ Orden #${sanitizeLog(req.params.id)} → '${sanitizeLog(status)}' por ${sanitizeLog(req.user.usuario)}`);
    res.json({ message: 'Status actualizado correctamente' });
  } catch (err) {
    console.error('Error actualizando status:', err.message);
    res.status(500).json({ error: 'Error actualizando status', detalle: err.message });
  }
});

// ================================
// ➕ POST /  — crear pedido (cliente logueado)
// ================================
router.post('/', authMiddleware, async (req, res) => {
  const { total, items } = req.body;
  if (!items || !Array.isArray(items) || items.length === 0)
    return res.status(400).json({ error: 'El pedido no tiene productos' });
  if (!total || total <= 0)
    return res.status(400).json({ error: 'Total inválido' });

  try {
    const db = await getDB();
    const itemsConSucursal = [];

    for (const item of items) {
      const { product_id, cantidad } = item;
      const [rows] = await db.execute(`
        SELECT i.branch_id, b.nombre, i.stock
        FROM inventory i JOIN branches b ON b.id = i.branch_id
        WHERE i.product_id = ? AND b.activo = 1 AND i.stock >= ?
        ORDER BY i.stock DESC LIMIT 1
      `, [product_id, cantidad]);

      if (rows.length === 0) {
        const [fallback] = await db.execute(`
          SELECT i.branch_id, b.nombre FROM inventory i
          JOIN branches b ON b.id = i.branch_id
          WHERE i.product_id = ? AND b.activo = 1 AND i.stock > 0
          ORDER BY i.stock DESC LIMIT 1
        `, [product_id]);
        const suc = fallback[0] || { branch_id: 1, nombre: 'Principal' };
        itemsConSucursal.push({ ...item, branch_id: suc.branch_id, branch_nombre: suc.nombre });
      } else {
        itemsConSucursal.push({ ...item, branch_id: rows[0].branch_id, branch_nombre: rows[0].nombre });
      }
    }

    const porSucursal = {};
    for (const item of itemsConSucursal) {
      const key = item.branch_id;
      if (!porSucursal[key])
        porSucursal[key] = { branch_id: item.branch_id, branch_nombre: item.branch_nombre, items: [], subtotal: 0 };
      porSucursal[key].items.push(item);
      porSucursal[key].subtotal += Number(item.subtotal);
    }

    const grupos = Object.values(porSucursal);

    // UUID compartido para agrupar todos los sub-pedidos de esta compra
    // Todos los INSERT de esta transacción usan el mismo pedido_ref
    const pedidoRef = require('crypto').randomUUID();

    // Obtener conexión individual para la transacción
    // db.execute() no soporta START TRANSACTION en mysql2 con pool
    const conn = await db.getConnection();
    const orderIds = [];

    try {
      await conn.beginTransaction();

      for (const grupo of grupos) {
        const [result] = await conn.execute(`
          INSERT INTO orders (user_id, sucursal, total, status, fecha, pedido_ref)
          VALUES (?, ?, ?, 'pendiente', NOW(), ?)
        `, [req.user.id, grupo.branch_id, grupo.subtotal, pedidoRef]);
        const orderId = result.insertId;
        orderIds.push({ orderId, sucursal: grupo.branch_nombre });
        for (const item of grupo.items) {
          await conn.execute(
            `INSERT INTO order_items (order_id, product_id, cantidad, subtotal) VALUES (?, ?, ?, ?)`,
            [orderId, item.product_id, item.cantidad, item.subtotal]
          );
        }
      }

      await conn.commit();
      conn.release();

      const sucursales = [...new Set(grupos.map(g => g.branch_nombre))];
      console.log(`✅ ${orderIds.length} pedido(s) | usuario ${req.user.id} | $${total} | ${sucursales.join(', ')}`);
      res.json({
        message:   'Pedido creado correctamente',
        orderId:   orderIds[0].orderId,
        pedidoRef,
        orderIds,
        sucursales,
        sucursal:  sucursales.length === 1 ? sucursales[0] : sucursales[0],
      });
    } catch (err) {
      await conn.rollback();
      conn.release();
      throw err;
    }
  } catch (err) {
    console.error('Error creando pedido:', err);
    res.status(500).json({ error: 'Error al procesar el pedido', detalle: err.message });
  }
});

// 🔔 GET /api/orders/nuevos
// Pedidos creados después de ?since=ISO_DATE
// Solo admin — para el sistema de notificaciones del panel
router.get('/nuevos', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db    = await getDB();
    const since = req.query.since || new Date(Date.now() - 60000).toISOString();

    const [pedidos] = await db.execute(`
      SELECT o.id, o.total, o.status, o.fecha, o.sucursal,
             b.nombre AS sucursal_nombre,
             u.nombre AS cliente_nombre, u.apellidoP AS cliente_apellido,
             COUNT(oi.id) AS num_items
      FROM orders o
      LEFT JOIN branches b ON b.id = o.sucursal
      LEFT JOIN users    u ON u.id = o.user_id
      LEFT JOIN order_items oi ON oi.order_id = o.id
      WHERE o.fecha > ?
      GROUP BY o.id
      ORDER BY o.fecha DESC
    `, [since]);

    res.json({ pedidos, total: pedidos.length });
  } catch (err) {
    console.error('Error obteniendo pedidos nuevos:', err.message);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;