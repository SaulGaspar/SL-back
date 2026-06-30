const express = require('express');
const { getDB } = require('../../config/db');
const { authMiddleware, adminOnly } = require('../../middlewares/auth');
const { createTransporter } = require('../../helpers/mailer');
const {
  ensurePromotionsTable,
  normalizePromotion,
  validatePromotion,
  escapeHtml,
} = require('../../helpers/promotionsStore');

const router = express.Router();

router.use(authMiddleware, adminOnly);
router.use(async (_req, res, next) => {
  try {
    await ensurePromotionsTable();
    next();
  } catch (error) {
    console.error('Error preparando promociones:', error);
    res.status(500).json({ error: 'No se pudo preparar el módulo de promociones' });
  }
});

async function notifyCustomers(promotion) {
  if (!process.env.EMAIL_HOST || !process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    return { sent: 0, warning: 'Promoción guardada, pero el correo no está configurado' };
  }

  const db = await getDB();
  const [users] = await db.execute(`
    SELECT correo
    FROM users
    WHERE rol = 'cliente'
      AND verificado = 1
      AND correo IS NOT NULL
      AND TRIM(correo) <> ''
  `);

  const recipients = [...new Set(users.map((user) => user.correo).filter(Boolean))];
  if (recipients.length === 0) return { sent: 0 };

  const discount =
    promotion.discount_type === 'percentage'
      ? `${promotion.discount_value}%`
      : new Intl.NumberFormat('es-MX', {
          style: 'currency',
          currency: 'MXN',
        }).format(promotion.discount_value);

  const scope =
    promotion.applies_to === 'all'
      ? 'todos los productos participantes'
      : `${promotion.applies_to === 'category' ? 'la categoría' : 'el producto'} ${promotion.target}`;

  const transporter = createTransporter();
  await transporter.sendMail({
    from: `"SportLike" <${process.env.EMAIL_USER}>`,
    to: process.env.EMAIL_USER,
    bcc: recipients,
    subject: `Nueva promoción SportLike: ${promotion.name}`,
    html: `
      <div style="font-family:Arial,sans-serif;max-width:620px;margin:auto;color:#0b2545">
        <h2 style="margin-bottom:8px">${escapeHtml(promotion.name)}</h2>
        <p>${escapeHtml(promotion.description)}</p>
        <p><strong>Descuento:</strong> ${escapeHtml(discount)}</p>
        <p><strong>Aplica a:</strong> ${escapeHtml(scope)}</p>
        <p><strong>Vigencia:</strong> ${escapeHtml(promotion.start_date)} al ${escapeHtml(promotion.end_date)}</p>
        <p>
          <a href="${escapeHtml(process.env.CLIENT_URL || 'https://sportlikeapps.netlify.app')}/promociones"
             style="display:inline-block;padding:12px 20px;background:#0b2545;color:white;text-decoration:none;border-radius:8px">
            Ver promoción
          </a>
        </p>
      </div>
    `,
  });

  return { sent: recipients.length };
}

router.get('/', async (_req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT *
      FROM promotions
      ORDER BY created_at DESC, id DESC
    `);
    res.json(rows);
  } catch (error) {
    console.error('Error listando promociones:', error);
    res.status(500).json({ error: 'No se pudieron consultar las promociones' });
  }
});

router.post('/', async (req, res) => {
  try {
    const promotion = normalizePromotion(req.body);
    const errors = validatePromotion(promotion);
    if (errors.length) return res.status(400).json({ error: errors.join('. ') });

    const db = await getDB();
    const [result] = await db.execute(
      `INSERT INTO promotions
        (name, description, discount_type, discount_value, applies_to, target,
         start_date, end_date, status, created_by)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        promotion.name,
        promotion.description,
        promotion.discount_type,
        promotion.discount_value,
        promotion.applies_to,
        promotion.target,
        promotion.start_date,
        promotion.end_date,
        promotion.status,
        req.user.id,
      ]
    );

    let notification = { sent: 0 };
    if (promotion.status === 'active') {
      try {
        notification = await notifyCustomers(promotion);
        if (notification.sent > 0) {
          await db.execute('UPDATE promotions SET notified_at = NOW() WHERE id = ?', [
            result.insertId,
          ]);
        }
      } catch (mailError) {
        console.error('Promoción guardada, correo no enviado:', mailError);
        notification = {
          sent: 0,
          warning: 'Promoción guardada, pero no fue posible enviar los correos',
        };
      }
    }

    const [[created]] = await db.execute('SELECT * FROM promotions WHERE id = ?', [
      result.insertId,
    ]);
    res.status(201).json({ promotion: created, notification });
  } catch (error) {
    console.error('Error creando promoción:', error);
    res.status(500).json({ error: 'No se pudo registrar la promoción' });
  }
});

router.put('/:id', async (req, res) => {
  try {
    const promotion = normalizePromotion(req.body);
    const errors = validatePromotion(promotion);
    if (errors.length) return res.status(400).json({ error: errors.join('. ') });

    const db = await getDB();
    const [result] = await db.execute(
      `UPDATE promotions
       SET name = ?, description = ?, discount_type = ?, discount_value = ?,
           applies_to = ?, target = ?, start_date = ?, end_date = ?, status = ?
       WHERE id = ?`,
      [
        promotion.name,
        promotion.description,
        promotion.discount_type,
        promotion.discount_value,
        promotion.applies_to,
        promotion.target,
        promotion.start_date,
        promotion.end_date,
        promotion.status,
        req.params.id,
      ]
    );

    if (!result.affectedRows) return res.status(404).json({ error: 'Promoción no encontrada' });
    const [[updated]] = await db.execute('SELECT * FROM promotions WHERE id = ?', [
      req.params.id,
    ]);
    res.json(updated);
  } catch (error) {
    console.error('Error actualizando promoción:', error);
    res.status(500).json({ error: 'No se pudo actualizar la promoción' });
  }
});

router.patch('/:id/toggle', async (req, res) => {
  try {
    const status = req.body.status;
    if (!['active', 'inactive'].includes(status)) {
      return res.status(400).json({ error: 'Estado no válido' });
    }

    const db = await getDB();
    const [result] = await db.execute(
      'UPDATE promotions SET status = ? WHERE id = ?',
      [status, req.params.id]
    );
    if (!result.affectedRows) return res.status(404).json({ error: 'Promoción no encontrada' });
    res.json({ message: 'Estado actualizado', status });
  } catch (error) {
    console.error('Error cambiando estado de promoción:', error);
    res.status(500).json({ error: 'No se pudo cambiar el estado' });
  }
});

router.post('/:id/notify', async (req, res) => {
  try {
    const db = await getDB();
    const [[promotion]] = await db.execute(
      'SELECT * FROM promotions WHERE id = ?',
      [req.params.id]
    );
    if (!promotion) return res.status(404).json({ error: 'Promoción no encontrada' });
    if (promotion.status !== 'active') {
      return res.status(400).json({ error: 'Solo se notifican promociones activas' });
    }

    const notification = await notifyCustomers(promotion);
    if (notification.sent > 0) {
      await db.execute('UPDATE promotions SET notified_at = NOW() WHERE id = ?', [
        req.params.id,
      ]);
    }
    res.json(notification);
  } catch (error) {
    console.error('Error notificando promoción:', error);
    res.status(500).json({ error: 'No se pudieron enviar los correos' });
  }
});

router.delete('/:id', async (req, res) => {
  try {
    const db = await getDB();
    const [result] = await db.execute('DELETE FROM promotions WHERE id = ?', [
      req.params.id,
    ]);
    if (!result.affectedRows) return res.status(404).json({ error: 'Promoción no encontrada' });
    res.json({ message: 'Promoción eliminada' });
  } catch (error) {
    console.error('Error eliminando promoción:', error);
    res.status(500).json({ error: 'No se pudo eliminar la promoción' });
  }
});

module.exports = router;
