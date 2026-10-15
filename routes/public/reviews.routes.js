const express = require('express');
const router = express.Router();

const { getDB } = require('../../config/db');
const { authMiddleware } = require('../../middlewares/auth');

function validProductId(value) {
  const id = Number(value);
  return Number.isInteger(id) && id > 0 ? id : null;
}

router.get('/product/:productId', async (req, res) => {
  const productId = validProductId(req.params.productId);
  const limit = Math.min(Math.max(Number(req.query.limit) || 6, 1), 20);
  const offset = Math.max(Number(req.query.offset) || 0, 0);
  if (!productId) return res.status(400).json({ error: 'Producto inválido.' });

  try {
    const db = await getDB();
    const [[summary]] = await db.execute(
      `SELECT COUNT(*) AS count, COALESCE(ROUND(AVG(calificacion), 1), 0) AS average
       FROM resenas_productos
       WHERE producto_id = ? AND estado = 'publicada'`,
      [productId]
    );
    const [reviews] = await db.execute(
      `SELECT r.id, r.calificacion AS rating, r.comentario AS comment, r.creado_en AS created_at,
              CONCAT(u.nombre, ' ', LEFT(u.apellidoP, 1), '.') AS author
       FROM resenas_productos r
       JOIN users u ON u.id = r.usuario_id
       WHERE r.producto_id = ? AND r.estado = 'publicada'
       ORDER BY r.creado_en DESC
       LIMIT ? OFFSET ?`,
      [productId, limit, offset]
    );
    res.json({ summary: { count: Number(summary.count), average: Number(summary.average) }, reviews });
  } catch (error) {
    console.error('Error consultando reseñas:', error.message);
    res.status(500).json({ error: 'No se pudieron cargar las reseñas.' });
  }
});

router.get('/product/:productId/mine', authMiddleware, async (req, res) => {
  const productId = validProductId(req.params.productId);
  if (!productId) return res.status(400).json({ error: 'Producto inválido.' });

  try {
    const db = await getDB();
    const [[review]] = await db.execute(
      `SELECT id, calificacion AS rating, comentario AS comment, estado AS status,
              creado_en AS created_at, actualizado_en AS updated_at
       FROM resenas_productos WHERE producto_id = ? AND usuario_id = ?`,
      [productId, req.user.id]
    );
    res.json({ review: review || null });
  } catch (error) {
    console.error('Error consultando reseña del cliente:', error.message);
    res.status(500).json({ error: 'No se pudo consultar tu reseña.' });
  }
});

router.post('/product/:productId', authMiddleware, async (req, res) => {
  const productId = validProductId(req.params.productId);
  const rating = Number(req.body?.rating);
  const comment = String(req.body?.comment || '').trim();
  if (!productId) return res.status(400).json({ error: 'Producto inválido.' });
  if (!Number.isInteger(rating) || rating < 1 || rating > 5) {
    return res.status(400).json({ error: 'Selecciona una calificación de 1 a 5 estrellas.' });
  }
  if (comment.length > 500) return res.status(400).json({ error: 'El comentario no puede exceder 500 caracteres.' });

  try {
    const db = await getDB();
    const [[purchase]] = await db.execute(
      `SELECT 1
       FROM orders o
       JOIN order_items oi ON oi.order_id = o.id
       WHERE o.user_id = ? AND oi.product_id = ? AND o.status = 'entregado'
       LIMIT 1`,
      [req.user.id, productId]
    );
    if (!purchase) {
      return res.status(403).json({ error: 'Solo clientes con una compra entregada pueden opinar.' });
    }

    await db.execute(
      `INSERT INTO resenas_productos (producto_id, usuario_id, calificacion, comentario, estado, notas_admin)
       VALUES (?, ?, ?, ?, 'pendiente', NULL)
       ON DUPLICATE KEY UPDATE
         calificacion = VALUES(calificacion), comentario = VALUES(comentario), estado = 'pendiente', notas_admin = NULL`,
      [productId, req.user.id, rating, comment || null]
    );
    res.status(201).json({ message: 'Tu reseña se envió para revisión.' });
  } catch (error) {
    console.error('Error guardando reseña:', error.message);
    res.status(500).json({ error: 'No se pudo guardar tu reseña.' });
  }
});

module.exports = router;
