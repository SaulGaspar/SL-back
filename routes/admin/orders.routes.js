const express = require('express');
const router  = express.Router();

const { getDB }          = require('../../config/db');
const { authMiddleware, adminOnly } = require('../../middlewares/auth');
const { sanitizeLog }    = require('../../helpers/sanitizeLog');
const {
  getApprovedPaymentForUser,
} = require('../../helpers/mercadoPago');

const {createPaidOrder}=require('../../helpers/createPaidOrder');
const {allowedOrderStatuses,changeOrderStatus}=require('../../helpers/orderStatus');
const { buildOrderFilter, orderSummarySQL, withLegacyAliases, normalizeOrderStatus } = require('../../helpers/orderStats');

// ================================
// 📊 GET /stats/summary
// ================================
router.get('/stats/summary', authMiddleware, adminOnly, async (req, res) => {
  try {
    const {where,params} = buildOrderFilter(req.query);
    const db = await getDB();
    const [stats] = await db.execute(orderSummarySQL(where),params);
    const [porSucursal] = await db.execute(`
      SELECT o.sucursal,b.nombre AS nombre_sucursal,COUNT(*) AS ordenes,
        COALESCE(SUM(CASE WHEN o.status <> 'cancelado' THEN o.total ELSE 0 END),0) AS ingresos
      FROM orders o LEFT JOIN branches b ON b.id = o.sucursal
      ${where} GROUP BY o.sucursal,b.nombre ORDER BY ingresos DESC`,params);
    const [ventasPorDia] = await db.execute(`
      SELECT DATE(o.fecha) AS dia,COUNT(*) AS ordenes,COALESCE(SUM(o.total),0) AS ingresos
      FROM orders o ${where} AND o.status <> 'cancelado'
      ${req.query.from || req.query.to ? '' : 'AND o.fecha >= DATE_SUB(NOW(), INTERVAL 30 DAY)'}
      GROUP BY dia ORDER BY dia`,params);
    res.json({resumen:withLegacyAliases(stats[0]),porSucursal,ventasPorDia});
  } catch (error) {
    console.error('Error obteniendo estadísticas:',error.message);
    res.status(error.statusCode || 500).json({error:error.statusCode ? error.message : 'No se pudieron consultar las estadísticas.'});
  }
});

// ================================
// 🔔 GET /api/orders/notificaciones
// ================================
router.get('/notificaciones', authMiddleware, async (req, res) => {
  try {
    const db    = await getDB();

    const [pedidos] = await db.execute(`
      SELECT o.id, o.total, o.status, o.fecha, o.sucursal,
             b.nombre AS sucursal_nombre,
             COALESCE(o.pedido_ref, CAST(o.id AS CHAR)) AS pedido_ref
      FROM orders o
      LEFT JOIN branches b ON b.id = o.sucursal
      WHERE o.user_id = ?
        AND o.fecha >= DATE_SUB(NOW(), INTERVAL 7 DAY)
      ORDER BY o.fecha DESC
      LIMIT 20
    `, [req.user.id]);

    res.json({ pedidos, total: pedidos.length });
  } catch (err) {
    console.error('Error notificaciones cliente:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ================================
// 🔔 GET /nuevos — pedidos recientes para notificaciones admin
// ================================
router.get('/nuevos', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db    = await getDB();
    const since = req.query.since || new Date(Date.now() - 60000).toISOString();

    const [pedidos] = await db.execute(`
      SELECT o.id, o.total, o.status, o.fecha, o.sucursal,
             b.nombre AS sucursal_nombre,
             u.nombre AS cliente_nombre,
             u.apellidoP AS cliente_apellido,
             COUNT(oi.id) AS num_items
      FROM orders o
      LEFT JOIN branches b ON b.id = o.sucursal
      LEFT JOIN users u ON u.id = o.user_id
      LEFT JOIN order_items oi ON oi.order_id = o.id
      WHERE o.fecha > ?
      GROUP BY o.id
      ORDER BY o.fecha DESC
    `, [since]);

    res.json({ pedidos, total: pedidos.length });
  } catch (err) {
    console.error('Error notificaciones:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ================================
// 📋 GET /mis-pedidos  ← cliente logueado
// ⚠️  ANTES de /:id
// ================================
router.get('/mis-pedidos', authMiddleware, async (req, res) => {
  try {
    const db = await getDB();

    const [rows] = await db.execute(`
      SELECT o.id, o.total, o.status, o.fecha, o.sucursal,
             b.nombre AS sucursal_nombre,
             COALESCE(o.pedido_ref, CAST(o.id AS CHAR)) AS pedido_ref
      FROM orders o
      LEFT JOIN branches b ON b.id = o.sucursal
      WHERE o.user_id = ?
      ORDER BY o.fecha DESC
    `, [req.user.id]);

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

    for (const grupo of Object.values(mapaGrupos)) {
      for (const subId of grupo.subIds) {
        try {
          const [items] = await db.execute(`
            SELECT oi.*,
                   p.nombre, p.imagen, p.categoria, p.marca
            FROM order_items oi
            JOIN products p ON p.id = oi.product_id
            WHERE oi.order_id = ?
          `, [subId]);
          grupo.items.push(...items);
        } catch { /* skip */ }
      }
      delete grupo.subIds;
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
    const filter = buildOrderFilter(req.query);
    const db = await getDB();
    let sql = `
      SELECT o.id, o.user_id, o.total, o.fecha, o.status, o.sucursal,
             u.nombre, u.apellidoP, u.usuario, u.correo
      FROM orders o
      LEFT JOIN users u ON u.id = o.user_id
      ${filter.where}
    `;
    const params = [...filter.params];
    if (status && status !== 'all') {
      if (status === 'preparando') { sql += " AND o.status IN ('preparando','procesando')"; }
      else if (status === 'en_camino') { sql += " AND o.status IN ('en_camino','enviado')"; }
      else { sql += ' AND o.status = ?'; params.push(status); }
    }
    if (user_id) { sql += ' AND o.user_id = ?'; params.push(user_id); }
    sql += ' ORDER BY o.fecha DESC';
    const limitNum = parseInt(limit);
    if (limitNum > 0) sql += ` LIMIT ${limitNum}`;
    const [rows] = await db.execute(sql, params);
    res.json(rows.map(order => ({...order,status:normalizeOrderStatus(order.status)})));
  } catch (err) {
    console.error('Error obteniendo órdenes:', err.message);
    res.status(err.statusCode || 500).json({ error: err.statusCode ? err.message : 'Error obteniendo órdenes' });
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
    res.json({ order: {...order[0],status:normalizeOrderStatus(order[0].status)}, items, allowed_statuses:allowedOrderStatuses(order[0].status) });
  } catch (err) {
    console.error('Error obteniendo orden:', err.message);
    res.status(500).json({ error: 'Error obteniendo orden', detalle: err.message });
  }
});

// ================================
// 🔄 PATCH /:id/status  (admin)
// ================================
router.patch('/:id/status', authMiddleware, adminOnly, async (req, res) => {
  try {
    const result=await changeOrderStatus(await getDB(),req.params.id,req.body.status,req.body.confirm_cancellation,req.user);
    console.log(`Orden #${sanitizeLog(req.params.id)} → '${sanitizeLog(req.body.status)}' por ${sanitizeLog(req.user.usuario)}`);
    res.json(result);
  }catch(error){console.error('Error actualizando estado:',error.message);res.status(error.statusCode||500).json({error:error.statusCode?error.message:'No se pudo actualizar el estado del pedido.'});}
});

// ================================
// ➕ POST /  — crear pedido (cliente logueado)
// Alias compatible: usa la misma transacción y protección por pago que /payments/complete.
// ================================
router.post('/', authMiddleware, async (req, res) => {
  try {
    if(!req.body.payment_id)return res.status(402).json({error:'Debes completar el pago con Mercado Pago.'});
    const payment=await getApprovedPaymentForUser(req.body.payment_id,req.user.id);
    const result=await createPaidOrder({payment,userId:req.user.id,addressId:req.body.direccion_id,items:req.body.items});
    res.json(result);
  }catch(error){console.error('Error creando pedido:',error.message);res.status(error.statusCode||500).json({error:error.statusCode?error.message:'No se pudo completar el pedido pagado.',payment_status:error.paymentStatus});}
});

module.exports = router;
