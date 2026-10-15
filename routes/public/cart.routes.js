const express = require('express');
const router = express.Router();

const { getDB } = require('../../config/db');
const { getCartRecommendations } = require('../../services/apriori.service');

function readProductIds(body = {}) {
  const values = body.productIds || body.product_ids || body.products || body.items || [];
  if (!Array.isArray(values)) return [];
  const ids = [];
  for (const value of values) {
    const raw = typeof value === 'object' && value !== null
      ? value.product_id ?? value.productId ?? value.id
      : value;
    const id = Number(raw);
    if (Number.isInteger(id) && id > 0 && !ids.includes(id)) ids.push(id);
  }
  return ids;
}

router.post('/recommendations', async (req, res) => {
  const productIds = readProductIds(req.body);
  const limit = Math.min(Math.max(Number(req.body?.limit) || Number(req.query.limit) || 6, 1), 12);

  if (!productIds.length) {
    return res.status(400).json({ error: 'El carrito no contiene productos v?lidos' });
  }

  try {
    const db = await getDB();
    const recommendations = await getCartRecommendations(db, productIds, limit);
    res.json({ source: 'apriori-cart', antecedents: productIds, recommendations });
  } catch (err) {
    console.error('Error obteniendo recomendaciones de carrito:', err.message);
    res.status(500).json({ error: 'Error obteniendo recomendaciones de carrito' });
  }
});

module.exports = router;
