const express = require('express');
const { getDB } = require('../../config/db');
const { authMiddleware, adminOnly } = require('../../middlewares/auth');
const { createTransporter } = require('../../helpers/mailer');
const { ensureReturnsTable } = require('../../helpers/returnsStore');
const { escapeHtml } = require('../../helpers/promotionsStore');

const router = express.Router();

router.use(authMiddleware, adminOnly);
router.use(async (_req, res, next) => {
  try {
    await ensureReturnsTable();
    next();
  } catch (error) {
    console.error('Error preparando devoluciones:', error);
    res.status(500).json({ error: 'No se pudo preparar el módulo de devoluciones' });
  }
});

router.get('/', async (req, res) => {
  try {
    const db = await getDB();
    const params = [];
    let where = '';
    if (req.query.status && req.query.status !== 'all') {
      where = 'WHERE r.status = ?';
      params.push(req.query.status);
    }

    const [rows] = await db.execute(
      `SELECT r.*, o.fecha AS order_date,
              COALESCE(o.pedido_ref, CAST(o.id AS CHAR)) AS pedido_ref,
              u.nombre, u.apellidoP, u.correo,
              b.nombre AS sucursal_nombre
       FROM return_requests r
       JOIN orders o ON o.id = r.order_id
       JOIN users u ON u.id = r.user_id
       LEFT JOIN branches b ON b.id = o.sucursal
       ${where}
       ORDER BY
         FIELD(r.status, 'requested', 'reviewing', 'approved', 'rejected', 'refunded'),
         r.created_at DESC`,
      params
    );
    res.json(rows);
  } catch (error) {
    console.error('Error listando devoluciones admin:', error);
    res.status(500).json({ error: 'No se pudieron consultar las devoluciones' });
  }
});

router.patch('/:id/status', async (req, res) => {
  const status = String(req.body.status || '');
  const adminNotes = String(req.body.admin_notes || '').trim() || null;
  const validStatuses = ['reviewing', 'approved', 'rejected', 'refunded'];

  if (!validStatuses.includes(status)) {
    return res.status(400).json({ error: 'Estado de devolución no válido' });
  }

  try {
    const db = await getDB();
    const [result] = await db.execute(
      `UPDATE return_requests
       SET status = ?, admin_notes = ?, reviewed_by = ?, reviewed_at = NOW()
       WHERE id = ?`,
      [status, adminNotes, req.user.id, req.params.id]
    );
    if (!result.affectedRows) {
      return res.status(404).json({ error: 'Solicitud no encontrada' });
    }

    const [[row]] = await db.execute(
      `SELECT r.*, u.correo, u.nombre
       FROM return_requests r
       JOIN users u ON u.id = r.user_id
       WHERE r.id = ?`,
      [req.params.id]
    );

    let mailWarning = null;
    if (
      row?.correo &&
      process.env.EMAIL_HOST &&
      process.env.EMAIL_USER &&
      process.env.EMAIL_PASS
    ) {
      try {
        const labels = {
          reviewing: 'en revisión',
          approved: 'aprobada',
          rejected: 'rechazada',
          refunded: 'reembolsada',
        };
        await createTransporter().sendMail({
          from: `"SportLike" <${process.env.EMAIL_USER}>`,
          to: row.correo,
          subject: `Actualización de devolución #${row.id}`,
          html: `
            <p>Hola ${escapeHtml(row.nombre || 'cliente')},</p>
            <p>Tu solicitud de devolución ahora está <strong>${labels[status]}</strong>.</p>
            ${adminNotes ? `<p><strong>Observaciones:</strong> ${escapeHtml(adminNotes)}</p>` : ''}
            <p>SportLike</p>
          `,
        });
      } catch (mailError) {
        console.error('Estado actualizado, correo no enviado:', mailError);
        mailWarning = 'Estado actualizado, pero no se pudo enviar el correo';
      }
    }

    res.json({ message: 'Estado actualizado', warning: mailWarning });
  } catch (error) {
    console.error('Error actualizando devolución:', error);
    res.status(500).json({ error: 'No se pudo actualizar la devolución' });
  }
});

module.exports = router;
