const { getDB } = require('../config/db');
const { hashCartItems } = require('./mercadoPago');

function orderError(message, statusCode = 400, extra = {}) {
  const error = new Error(message);
  error.statusCode = statusCode;
  Object.assign(error, extra);
  return error;
}

function normalizeItems(rawItems) {
  if (!Array.isArray(rawItems) || rawItems.length === 0 || rawItems.length > 50) {
    throw orderError('El pedido no tiene productos válidos');
  }

  const merged = new Map();
  for (const item of rawItems) {
    const productId = Number(item.product_id);
    const quantity = Number(item.cantidad);
    if (!Number.isInteger(productId) || productId <= 0) {
      throw orderError('El pedido contiene un producto inválido');
    }
    if (!Number.isInteger(quantity) || quantity <= 0 || quantity > 20) {
      throw orderError('El pedido contiene una cantidad inválida');
    }
    merged.set(productId, (merged.get(productId) || 0) + quantity);
  }

  return [...merged.entries()]
    .map(([product_id, cantidad]) => ({ product_id, cantidad }))
    .sort((a, b) => a.product_id - b.product_id);
}

function paymentOwnerId(payment) {
  const metadataUser = payment?.metadata?.user_id;
  if (metadataUser !== undefined && metadataUser !== null) {
    return String(metadataUser);
  }
  const match = String(payment?.external_reference || '').match(/^sportlike:(\d+):/);
  return match ? match[1] : '';
}

function existingOrderResponse(existingOrders, payment) {
  const sucursales = [
    ...new Set(existingOrders.map((order) => order.sucursal).filter(Boolean)),
  ];
  return {
    message: 'El pedido de este pago ya estaba registrado',
    alreadyProcessed: true,
    orderId: existingOrders[0].orderId,
    pedidoRef: `MP-${payment.id}`,
    orderIds: existingOrders,
    sucursales,
    sucursal: sucursales[0] || '',
    paymentId: payment.id,
    paidTotal: Number(payment.transaction_amount),
  };
}

async function createPaidOrder({ payment, userId, addressId, items: rawItems }) {
  const items = normalizeItems(rawItems);

  if (!payment?.id || payment.status !== 'approved') {
    throw orderError('El pago todavía no está aprobado', 402, {
      paymentStatus: payment?.status,
    });
  }
  if (paymentOwnerId(payment) !== String(userId)) {
    throw orderError('El pago no corresponde al usuario', 403);
  }
  if (
    payment?.metadata?.address_id !== undefined &&
    payment?.metadata?.address_id !== null &&
    String(payment.metadata.address_id) !== String(addressId)
  ) {
    throw orderError('La dirección no coincide con la utilizada durante el pago');
  }
  if (
    payment?.metadata?.cart_hash &&
    payment.metadata.cart_hash !== hashCartItems(items)
  ) {
    throw orderError('El carrito no coincide con los productos pagados');
  }

  const db = await getDB();
  const conn = await db.getConnection();
  const pedidoRef = `MP-${payment.id}`;
  const lockName = `sportlike_mp_${payment.id}`;
  let lockAcquired = false;
  let transactionStarted = false;

  try {
    const [[lock]] = await conn.execute('SELECT GET_LOCK(?, 8) AS acquired', [lockName]);
    lockAcquired = Number(lock?.acquired) === 1;
    if (!lockAcquired) {
      throw orderError('El pago se está procesando. Intenta consultar nuevamente.', 409);
    }

    const [existingOrders] = await conn.execute(
      `SELECT o.id AS orderId, o.pedido_ref AS pedidoRef, b.nombre AS sucursal
       FROM orders o
       LEFT JOIN branches b ON b.id = o.sucursal
       WHERE o.user_id = ? AND o.pedido_ref = ?
       ORDER BY o.id`,
      [userId, pedidoRef]
    );
    if (existingOrders.length > 0) {
      return existingOrderResponse(existingOrders, payment);
    }

    await conn.beginTransaction();
    transactionStarted = true;

    const [[address]] = await conn.execute(
      'SELECT id FROM direcciones WHERE id = ? AND usuario_id = ?',
      [addressId, userId]
    );
    if (!address) {
      throw orderError('La dirección seleccionada no es válida');
    }

    const itemsWithBranch = [];
    for (const item of items) {
      const [rows] = await conn.execute(
        `SELECT i.branch_id, b.nombre, i.stock, p.nombre AS product_name, p.precio
         FROM inventory i
         JOIN branches b ON b.id = i.branch_id
         JOIN products p ON p.id = i.product_id
         WHERE i.product_id = ?
           AND b.activo = 1
           AND p.activo = 1
           AND i.stock >= ?
         ORDER BY i.stock DESC
         LIMIT 1
         FOR UPDATE`,
        [item.product_id, item.cantidad]
      );

      if (rows.length === 0) {
        const [[product]] = await conn.execute(
          'SELECT nombre FROM products WHERE id = ?',
          [item.product_id]
        );
        throw orderError(
          `Stock insuficiente para "${product?.nombre || `Producto ID ${item.product_id}`}". Contacta a SportLike para revisar el pago.`,
          409,
          { product_id: item.product_id }
        );
      }

      itemsWithBranch.push({
        ...item,
        subtotal: Number(rows[0].precio) * item.cantidad,
        branch_id: rows[0].branch_id,
        branch_nombre: rows[0].nombre,
      });
    }

    const productsTotal = itemsWithBranch.reduce(
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
      throw orderError('El monto pagado no coincide con el total actual del carrito');
    }

    const byBranch = {};
    for (const item of itemsWithBranch) {
      if (!byBranch[item.branch_id]) {
        byBranch[item.branch_id] = {
          branch_id: item.branch_id,
          branch_nombre: item.branch_nombre,
          items: [],
          subtotal: 0,
        };
      }
      byBranch[item.branch_id].items.push(item);
      byBranch[item.branch_id].subtotal += Number(item.subtotal);
    }

    const groups = Object.values(byBranch);
    const orderIds = [];

    for (const group of groups) {
      const [result] = await conn.execute(
        `INSERT INTO orders (user_id, sucursal, total, status, fecha, pedido_ref)
         VALUES (?, ?, ?, 'pendiente', NOW(), ?)`,
        [userId, group.branch_id, group.subtotal, pedidoRef]
      );
      const orderId = result.insertId;
      orderIds.push({ orderId, sucursal: group.branch_nombre });

      for (const item of group.items) {
        await conn.execute(
          `INSERT INTO order_items (order_id, product_id, cantidad, subtotal)
           VALUES (?, ?, ?, ?)`,
          [orderId, item.product_id, item.cantidad, item.subtotal]
        );
        await conn.execute(
          `UPDATE inventory
           SET stock = GREATEST(stock - ?, 0)
           WHERE product_id = ? AND branch_id = ?`,
          [item.cantidad, item.product_id, group.branch_id]
        );
      }
    }

    await conn.commit();
    transactionStarted = false;

    const sucursales = [...new Set(groups.map((group) => group.branch_nombre))];
    console.log(
      `✅ ${orderIds.length} pedido(s) creado(s) | usuario ${userId} | pago MP ${payment.id} | $${paidAmount} | ${sucursales.join(', ')}`
    );

    return {
      message: 'Pedido creado correctamente',
      orderId: orderIds[0].orderId,
      pedidoRef,
      orderIds,
      sucursales,
      sucursal: sucursales[0] || '',
      paymentId: payment.id,
      paidTotal: paidAmount,
      shipping,
    };
  } catch (error) {
    if (transactionStarted) {
      await conn.rollback();
    }
    throw error;
  } finally {
    if (lockAcquired) {
      await conn.execute('SELECT RELEASE_LOCK(?)', [lockName]).catch(() => {});
    }
    conn.release();
  }
}

module.exports = { createPaidOrder, normalizeItems };
