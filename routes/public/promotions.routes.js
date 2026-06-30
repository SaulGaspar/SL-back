const express = require('express');
const { getDB } = require('../../config/db');
const { ensurePromotionsTable } = require('../../helpers/promotionsStore');

const router = express.Router();

router.get('/active', async (_req, res) => {
  try {
    await ensurePromotionsTable();
    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT id, name, description, discount_type, discount_value,
             applies_to, target, start_date, end_date
      FROM promotions
      WHERE status = 'active'
        AND CURDATE() BETWEEN start_date AND end_date
      ORDER BY discount_value DESC, created_at DESC
    `);
    res.json(rows);
  } catch (error) {
    console.error('Error consultando promociones públicas:', error);
    res.status(500).json({ error: 'No se pudieron consultar las promociones' });
  }
});

module.exports = router;
