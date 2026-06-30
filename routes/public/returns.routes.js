const express = require('express');
const { getDB } = require('../../config/db');
const { authMiddleware } = require('../../middlewares/auth');
const { ensureReturnsTable } = require('../../helpers/returnsStore');

const router = express.Router();

router.use(authMiddleware);
router.use(async (_req, res, next) => {
  try {
    await ensureReturnsTable();
    next();
  } catch (error) {
    console.error('Error preparando devoluciones:', error);
    res.status(500).json({ error: 'No se pudo preparar el módulo de devoluciones' });
  }
});

router.get('/eligible-orders', async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(
      `SELECT o.id, o.total, o.fecha, o.status,
              COALESCE(o.pedido_ref, CAST(o.id AS CHAR)) AS pedido_ref,
              b.nombre AS sucursal_nombre
       FROM orders o
       LEFT JOIN branches b ON b.id = o.sucursal
       LEFT JOIN return_requests r ON r.order_id = o.id
       WHERE o.user_id = ?
         AND o.status = 'entregado'
         AND r.id IS NULL
       ORDER BY o.fecha DESC`,
      [req.user.id]
    );
    res.json(rows);
  } catch (error) {
    console.error('Error consultando pedidos elegibles:', error);
    res.status(500).json({ error: 'No se pudieron consultar los pedidos entregados' });
  }
});

router.get('/', async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(
      `SELECT r.*, o.fecha AS order_date,
              COALESCE(o.pedido_ref, CAST(o.id AS CHAR)) AS pedido_ref,
              b.nombre AS sucursal_nombre
       FROM return_requests r
       JOIN orders o ON o.id = r.order_id
       LEFT JOIN branches b ON b.id = o.sucursal
       WHERE r.user_id = ?
       ORDER BY r.created_at DESC`,
      [req.user.id]
    );
    res.json(rows);
  } catch (error) {
    console.error('Error consultando devoluciones:', error);
    res.status(500).json({ error: 'No se pudieron consultar las devoluciones' });
  }
});

router.post('/', async (req, res) => {
  const orderId = Number(req.body.order_id);
  const reason = String(req.body.reason || '');
  const details = String(req.body.details || '').trim();
  const validReasons = ['damaged', 'wrong_item', 'size', 'quality', 'other'];

  if (!Number.isInteger(orderId) || orderId <= 0) {
    return res.status(400).json({ error: 'Selecciona un pedido válido' });
  }
  if (!validReasons.includes(reason)) {
    return res.status(400).json({ error: 'Selecciona el motivo de la devolución' });
  }
  if (details.length < 10 || details.length > 1500) {
    return res.status(400).json({
      error: 'La descripción debe tener entre 10 y 1500 caracteres',
    });
  }

  try {
    const db = await getDB();
    const [[order]] = await db.execute(
      `SELECT id, total, status
       FROM orders
       WHERE id = ? AND user_id = ?`,
      [orderId, req.user.id]
    );

    if (!order) return res.status(404).json({ error: 'Pedido no encontrado' });
    if (order.status !== 'entregado') {
      return res.status(400).json({
        error: 'Solo se puede solicitar devolución de pedidos entregados',
      });
    }

    const [result] = await db.execute(
      `INSERT INTO return_requests
        (order_id, user_id, reason, details, requested_amount)
       VALUES (?, ?, ?, ?, ?)`,
      [order.id, req.user.id, reason, details, order.total]
    );

    const [[created]] = await db.execute(
      'SELECT * FROM return_requests WHERE id = ?',
      [result.insertId]
    );
    res.status(201).json({
      message: 'Solicitud registrada. Será revisada con la empresa.',
      return_request: created,
    });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({
        error: 'Este pedido ya tiene una solicitud de devolución',
      });
    }
    console.error('Error registrando devolución:', error);
    res.status(500).json({ error: 'No se pudo registrar la devolución' });
  }
});

module.exports = router;
