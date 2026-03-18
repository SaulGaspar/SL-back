const express = require('express');
const router = express.Router();

const { getDB } = require('../../config/db');
const { authMiddleware, adminOnly } = require('../../middlewares/auth');
const { sanitizeLog } = require('../../helpers/sanitizeLog');

const STATUS_VALIDOS = ['pendiente', 'procesando', 'enviado', 'entregado', 'cancelado'];


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

// 📋 GET /api/admin/orders

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

// 📄 GET /api/admin/orders/:id

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

// 🔄 PATCH /api/admin/orders/:id/status

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

    console.log(`✅ Status de orden actualizado: Orden #${sanitizeLog(req.params.id)} → '${sanitizeLog(status)}' por admin ${sanitizeLog(req.user.usuario)}`);
    res.json({ message: 'Status actualizado correctamente' });
  } catch (err) {
    console.error('Error actualizando status de orden:', err.message);
    res.status(500).json({ error: 'Error actualizando status', detalle: err.message });
  }
});

// ➕ POST /api/orders

router.post('/', authMiddleware, async (req, res) => {
  const { total, items } = req.body;

  if (!items || !Array.isArray(items) || items.length === 0)
    return res.status(400).json({ error: 'El pedido no tiene productos' });
  if (!total || total <= 0)
    return res.status(400).json({ error: 'Total inválido' });

  try {
    const db = await getDB();

    // ── 1. Por cada producto, encontrar la sucursal con más stock ────
    const itemsConSucursal = [];

    for (const item of items) {
      const { product_id, cantidad, subtotal } = item;

      // Buscar sucursal activa con más stock de este producto
      const [rows] = await db.execute(`
        SELECT i.branch_id, b.nombre, i.stock
        FROM inventory i
        JOIN branches b ON b.id = i.branch_id
        WHERE i.product_id = ? AND b.activo = 1 AND i.stock >= ?
        ORDER BY i.stock DESC
        LIMIT 1
      `, [product_id, cantidad]);

      if (rows.length === 0) {
        // Sin stock en ninguna sucursal — buscar la que tenga algo aunque sea parcial
        const [fallback] = await db.execute(`
          SELECT i.branch_id, b.nombre, i.stock
          FROM inventory i
          JOIN branches b ON b.id = i.branch_id
          WHERE i.product_id = ? AND b.activo = 1 AND i.stock > 0
          ORDER BY i.stock DESC
          LIMIT 1
        `, [product_id]);

        // Si no hay stock en ningún lado, asignar sucursal 1 como fallback
        const sucursal = fallback[0] || { branch_id: 1, nombre: 'Principal' };
        itemsConSucursal.push({ ...item, branch_id: sucursal.branch_id, branch_nombre: sucursal.nombre });
      } else {
        itemsConSucursal.push({ ...item, branch_id: rows[0].branch_id, branch_nombre: rows[0].nombre });
      }
    }

    // ── 2. Agrupar items por sucursal ─
    const porSucursal = {};
    for (const item of itemsConSucursal) {
      const key = item.branch_id;
      if (!porSucursal[key]) {
        porSucursal[key] = {
          branch_id:    item.branch_id,
          branch_nombre: item.branch_nombre,
          items:         [],
          subtotal:      0,
        };
      }
      porSucursal[key].items.push(item);
      porSucursal[key].subtotal += Number(item.subtotal);
    }

    const grupos = Object.values(porSucursal);

    // ── 3. Crear un pedido por sucursal, en transacción ──
    await db.execute('START TRANSACTION');

    const orderIds = [];

    try {
      for (const grupo of grupos) {
        // Prorratear el total según el subtotal del grupo vs total global
        // (así la suma de los pedidos == total del carrito)
        const totalGrupo = grupo.subtotal;

        const [result] = await db.execute(`
          INSERT INTO orders (user_id, sucursal, total, status, fecha)
          VALUES (?, ?, ?, 'pendiente', NOW())
        `, [req.user.id, grupo.branch_id, totalGrupo]);

        const orderId = result.insertId;
        orderIds.push({ orderId, sucursal: grupo.branch_nombre });

        for (const item of grupo.items) {
          await db.execute(`
            INSERT INTO order_items (order_id, product_id, cantidad, subtotal)
            VALUES (?, ?, ?, ?)
          `, [orderId, item.product_id, item.cantidad, item.subtotal]);
        }
      }

      await db.execute('COMMIT');

      const sucursales = [...new Set(grupos.map(g => g.branch_nombre))];
      console.log(
        `✅ ${orderIds.length} pedido(s) creados | usuario ${req.user.id} | $${total}` +
        ` | sucursales: ${sucursales.join(', ')}`
      );

      res.json({
        message:   'Pedido creado correctamente',
        // Devolver el primer orderId como referencia principal para el cliente
        orderId:   orderIds[0].orderId,
        orderIds,
        sucursales,
        // Si fue a una sola sucursal mostrar su nombre, si fueron varias "varias sucursales"
        sucursal:  sucursales.length === 1 ? sucursales[0] : `${sucursales.length} sucursales`,
      });

    } catch (err) {
      await db.execute('ROLLBACK');
      throw err;
    }

  } catch (err) {
    console.error('Error creando pedido:', err);
    res.status(500).json({ error: 'Error al procesar el pedido', detalle: err.message });
  }
});

module.exports = router;