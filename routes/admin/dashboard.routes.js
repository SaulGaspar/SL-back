const express = require('express');
const router = express.Router();
const { getDB } = require('../../config/db');
const { authMiddleware, adminOnly } = require('../../middlewares/auth');
const { buildOrderFilter, orderSummarySQL, withLegacyAliases, normalizeOrderStatus } = require('../../helpers/orderStats');

router.get('/', authMiddleware, adminOnly, async (req, res) => {
  try {
    const {where,params} = buildOrderFilter(req.query);
    const db = await getDB();
    const salesWhere = where + " AND o.status <> 'cancelado'";
    const [summary] = await db.execute(orderSummarySQL(where),params);
    const [timeline] = await db.execute(`
      SELECT DATE(o.fecha) AS dia, COALESCE(SUM(o.total),0) AS total
      FROM orders o ${salesWhere} GROUP BY dia ORDER BY dia`,params);
    const [ranking] = await db.execute(`
      SELECT o.sucursal AS branch_id, COALESCE(b.nombre,CONCAT('Sucursal ',o.sucursal)) AS sucursal,
        COALESCE(SUM(o.total),0) AS ingresos
      FROM orders o LEFT JOIN branches b ON b.id = o.sucursal
      ${salesWhere} GROUP BY o.sucursal,b.nombre ORDER BY ingresos DESC`,params);
    const [topProducts] = await db.execute(`
      SELECT p.nombre,p.marca,SUM(oi.cantidad) AS vendidos,SUM(oi.subtotal) AS ingresos
      FROM order_items oi JOIN products p ON p.id = oi.product_id JOIN orders o ON o.id = oi.order_id
      ${salesWhere} GROUP BY p.id,p.nombre,p.marca ORDER BY vendidos DESC LIMIT 10`,params);
    const [recentOrders] = await db.execute(`
      SELECT o.id,o.total,o.fecha,o.status,o.sucursal,u.nombre,u.apellidoP
      FROM orders o LEFT JOIN users u ON u.id = o.user_id
      ${where} ORDER BY o.fecha DESC,o.id DESC LIMIT 6`,params);
    // El selector conserva sucursales aunque el período elegido no tenga ventas.
    const [branches] = await db.execute('SELECT id,nombre FROM branches ORDER BY nombre');
    res.json({resumen:withLegacyAliases(summary[0]),salesTimeline:timeline,branchRanking:ranking,topProducts,recentOrders:recentOrders.map(order=>({...order,status:normalizeOrderStatus(order.status)})),branches});
  } catch (error) {
    console.error('Error en resumen administrativo:',error.message);
    res.status(error.statusCode || 500).json({error:error.statusCode ? error.message : 'No se pudo consultar el resumen.'});
  }
});
module.exports = router;
