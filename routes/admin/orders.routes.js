const express = require('express');
const router  = express.Router();

const { getDB }          = require('../../config/db');
const { authMiddleware, adminOnly } = require('../../middlewares/auth');
const { sanitizeLog }    = require('../../helpers/sanitizeLog');
const {
  getApprovedPaymentForUser,
  hashCartItems,
} = require('../../helpers/mercadoPago');

const STATUS_VALIDOS = ['pendiente', 'preparando', 'en_camino', 'entregado', 'cancelado'];

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
            SELECT oi.cantidad, oi.subtotal,
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
// ✅ FIX: validación de stock DENTRO de la transacción con FOR UPDATE
// ================================
router.post('/', authMiddleware, async (req, res) => {
  const { items, direccion_id, payment_id } = req.body;

  if (!items || !Array.isArray(items) || items.length === 0)
    return res.status(400).json({ error: 'El pedido no tiene productos' });
  if (items.some((item) =>
    !Number.isInteger(Number(item.product_id)) ||
    Number(item.product_id) <= 0 ||
    !Number.isInteger(Number(item.cantidad)) ||
    Number(item.cantidad) <= 0 ||
    Number(item.cantidad) > 20
  )) {
    return res.status(400).json({ error: 'El pedido contiene productos o cantidades inválidas' });
  }
  if (!direccion_id)
    return res.status(400).json({ error: 'Debes seleccionar una dirección de envío antes de pagar' });
  if (!payment_id)
    return res.status(402).json({ error: 'Debes completar el pago con Mercado Pago' });

  let payment;
  try {
    payment = await getApprovedPaymentForUser(payment_id, req.user.id);
  } catch (error) {
    return res.status(error.statusCode || 500).json({
      error: error.message || 'No se pudo verificar el pago',
      payment_status: error.paymentStatus,
    });
  }

  const paymentAddressId = payment?.metadata?.address_id;
  if (
    paymentAddressId !== undefined &&
    paymentAddressId !== null &&
    String(paymentAddressId) !== String(direccion_id)
  ) {
    return res.status(400).json({
      error: 'La dirección no coincide con la utilizada durante el pago',
    });
  }
  if (
    payment?.metadata?.cart_hash &&
    payment.metadata.cart_hash !== hashCartItems(items)
  ) {
    return res.status(400).json({
      error: 'El carrito no coincide con los productos pagados',
    });
  }

  const pedidoRef = `MP-${payment.id}`;
  let db;
  let existingOrders;
  try {
    db = await getDB();
    [existingOrders] = await db.execute(
      `SELECT o.id AS orderId, o.pedido_ref AS pedidoRef, b.nombre AS sucursal
       FROM orders o
       LEFT JOIN branches b ON b.id = o.sucursal
       WHERE o.user_id = ? AND o.pedido_ref = ?
       ORDER BY o.id`,
      [req.user.id, pedidoRef]
    );
  } catch (error) {
    console.error('Error consultando pago ya procesado:', error.message);
    return res.status(500).json({ error: 'No se pudo validar el pedido pagado' });
  }

  if (existingOrders.length > 0) {
    const sucursales = [
      ...new Set(existingOrders.map((order) => order.sucursal).filter(Boolean)),
    ];
    return res.json({
      message: 'El pedido de este pago ya estaba registrado',
      alreadyProcessed: true,
      orderId: existingOrders[0].orderId,
      pedidoRef,
      orderIds: existingOrders,
      sucursales,
      sucursal: sucursales[0] || '',
      paymentId: payment.id,
    });
  }

  const conn = await db.getConnection();

  try {
    await conn.beginTransaction();

    const [direccion] = await conn.execute(
      'SELECT id FROM direcciones WHERE id = ? AND usuario_id = ?',
      [direccion_id, req.user.id]
    );

    if (direccion.length === 0) {
      await conn.rollback();
      conn.release();
      return res.status(400).json({ error: 'La dirección seleccionada no es válida' });
    }

    // ── 1. Validar stock Y asignar sucursal DENTRO de la transacción ──────────
    // FOR UPDATE bloquea las filas de inventory hasta el COMMIT,
    // evitando que otro pedido concurrente use el mismo stock.
    const itemsConSucursal = [];

    for (const item of items) {
      const { product_id, cantidad } = item;

      const [rows] = await conn.execute(`
        SELECT i.branch_id, b.nombre, i.stock,
               p.nombre AS product_name, p.precio
        FROM inventory i
        JOIN branches b ON b.id = i.branch_id
        JOIN products p ON p.id = i.product_id
        WHERE i.product_id = ?
          AND b.activo = 1
          AND p.activo = 1
          AND i.stock >= ?
        ORDER BY i.stock DESC
        LIMIT 1
        FOR UPDATE
      `, [product_id, cantidad]);

      if (rows.length === 0) {
        await conn.rollback();
        conn.release();

        const db = await getDB();
        const [pNombre] = await db.execute(
          'SELECT nombre FROM products WHERE id = ?', [product_id]
        );
        const nombre = pNombre[0]?.nombre || `Producto ID ${product_id}`;
        return res.status(400).json({
          error: `Stock insuficiente para "${nombre}". Verifica la disponibilidad e intenta de nuevo.`,
          product_id,
        });
      }

      itemsConSucursal.push({
        ...item,
        product_id,
        cantidad,
        subtotal: Number(rows[0].precio) * cantidad,
        branch_id:     rows[0].branch_id,
        branch_nombre: rows[0].nombre,
      });
    }

    const productsTotal = itemsConSucursal.reduce(
      (sum, item) => sum + Number(item.subtotal),
      0
    );
    const shipping = productsTotal >= 1500 ? 0 : 75;
    const expectedPaymentTotal = productsTotal + shipping;
    const paidAmount = Number(payment.transaction_amount);

    if (
      payment.currency_id !== 'MXN' ||
      !Number.isFinite(paidAmount) ||
      Math.abs(paidAmount - expectedPaymentTotal) > 0.01
    ) {
      await conn.rollback();
      conn.release();
      return res.status(400).json({
        error: 'El monto pagado no coincide con el total actual del carrito',
      });
    }

    // ── 2. Agrupar ítems por sucursal ─────────────────────────────────────────
    const porSucursal = {};
    for (const item of itemsConSucursal) {
      const key = item.branch_id;
      if (!porSucursal[key]) {
        porSucursal[key] = {
          branch_id:     item.branch_id,
          branch_nombre: item.branch_nombre,
          items:         [],
          subtotal:      0,
        };
      }
      porSucursal[key].items.push(item);
      porSucursal[key].subtotal += Number(item.subtotal);
    }

    const grupos    = Object.values(porSucursal);
    const orderIds  = [];

    for (const grupo of grupos) {
      // ── 3a. Crear la orden ────────────────────────────────────────────
      const [result] = await conn.execute(`
        INSERT INTO orders (user_id, sucursal, total, status, fecha, pedido_ref)
        VALUES (?, ?, ?, 'pendiente', NOW(), ?)
      `, [req.user.id, grupo.branch_id, grupo.subtotal, pedidoRef]);

      const orderId = result.insertId;
      orderIds.push({ orderId, sucursal: grupo.branch_nombre });

      for (const item of grupo.items) {
        // ── 3b. Insertar ítem del pedido ──────────────────────────────
        await conn.execute(
          `INSERT INTO order_items (order_id, product_id, cantidad, subtotal)
           VALUES (?, ?, ?, ?)`,
          [orderId, item.product_id, item.cantidad, item.subtotal]
        );

        // ── 3c. Descontar stock ───────────────────────────────────────
        // GREATEST(..., 0) es defensa adicional aunque FOR UPDATE ya garantiza stock >= cantidad
        await conn.execute(
          `UPDATE inventory
           SET stock = GREATEST(stock - ?, 0)
           WHERE product_id = ? AND branch_id = ?`,
          [item.cantidad, item.product_id, grupo.branch_id]
        );
      }
    }

    await conn.commit();
    conn.release();

    const sucursales = [...new Set(grupos.map(g => g.branch_nombre))];
    console.log(
      `✅ ${orderIds.length} pedido(s) creado(s) | usuario ${req.user.id} | pago MP ${payment.id} | $${paidAmount} | ${sucursales.join(', ')}`
    );

    res.json({
      message:   'Pedido creado correctamente',
      orderId:   orderIds[0].orderId,
      pedidoRef,
      orderIds,
      sucursales,
      sucursal:  sucursales[0],
      paymentId: payment.id,
      paidTotal: paidAmount,
      shipping,
    });

  } catch (err) {
    await conn.rollback();
    conn.release();
    console.error('Error creando pedido:', err);
    res.status(500).json({ error: 'Error al procesar el pedido', detalle: err.message });
  }
});

module.exports = router;
