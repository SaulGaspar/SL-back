const express = require('express');
const router = express.Router();
const { getDB } = require('../../config/db');
const { authMiddleware, adminOnly } = require('../../middlewares/auth');

router.use(authMiddleware, adminOnly);

router.get('/repurchase-propensity', async (req, res) => {
  const level = ['alta', 'media', 'baja'].includes(req.query.level) ? req.query.level : null;
  const search = String(req.query.search || '').trim();
  const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 500);

  try {
    const db = await getDB();
    const conditions = ["u.rol = 'cliente'"];
    const params = [];
    if (level) { conditions.push('rp.level = ?'); params.push(level); }
    if (search) {
      conditions.push('(u.nombre LIKE ? OR u.apellidoP LIKE ? OR u.usuario LIKE ? OR u.correo LIKE ?)');
      const query = `%${search}%`;
      params.push(query, query, query, query);
    }

    const [predictions] = await db.execute(`
      SELECT u.id AS user_id, u.nombre, u.apellidoP, u.usuario, u.correo,
        rp.probability, rp.level, rp.recency_days, rp.orders_90d, rp.spend_90d,
        rp.avg_ticket_90d, rp.units_90d, rp.product_diversity_90d,
        rp.previous_returns, rp.primary_factor, rp.generated_at
      FROM repurchase_predictions rp
      INNER JOIN users u ON u.id = rp.user_id
      WHERE ${conditions.join(' AND ')}
      ORDER BY rp.probability DESC, u.id
      LIMIT ${limit}
    `, params);

    const [[summary]] = await db.execute(`
      SELECT COUNT(*) AS total,
        SUM(level = 'alta') AS high_count,
        SUM(level = 'media') AS medium_count,
        SUM(level = 'baja') AS low_count,
        AVG(probability) AS average_probability,
        MAX(generated_at) AS generated_at
      FROM repurchase_predictions
    `);
    const [[model]] = await db.execute(`
      SELECT algorithm, metrics_json, dataset_rows, positive_rate, trained_at
      FROM ml_models WHERE name = 'repurchase_30d'
    `);

    res.json({
      predictions: predictions.map(item => ({
        ...item,
        probability: Number(item.probability),
        spend_90d: Number(item.spend_90d),
        avg_ticket_90d: Number(item.avg_ticket_90d),
      })),
      summary: {
        total: Number(summary.total || 0),
        high: Number(summary.high_count || 0),
        medium: Number(summary.medium_count || 0),
        low: Number(summary.low_count || 0),
        averageProbability: Number(summary.average_probability || 0),
        generatedAt: summary.generated_at,
      },
      model: model ? {
        algorithm: model.algorithm,
        metrics: JSON.parse(model.metrics_json || '{}'),
        datasetRows: Number(model.dataset_rows),
        positiveRate: Number(model.positive_rate),
        trainedAt: model.trained_at,
      } : null,
    });
  } catch (error) {
    console.error('Error consultando propensión de recompra:', error.message);
    res.status(500).json({ error: 'No se pudieron consultar las predicciones de recompra' });
  }
});

router.get('/customer-segments', async (req, res) => {
  const segment = ['Alto valor', 'Frecuente', 'Ocasional', 'En riesgo'].includes(req.query.segment) ? req.query.segment : null;
  const search = String(req.query.search || '').trim();
  const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 500);
  try {
    const db = await getDB();
    const conditions = ["u.rol = 'cliente'"];
    const params = [];
    if (segment) { conditions.push('cs.segment_name = ?'); params.push(segment); }
    if (search) {
      conditions.push('(u.nombre LIKE ? OR u.apellidoP LIKE ? OR u.usuario LIKE ? OR u.correo LIKE ?)');
      const query = `%${search}%`; params.push(query, query, query, query);
    }
    const [customers] = await db.execute(`
      SELECT u.id AS user_id, u.nombre, u.apellidoP, u.usuario, u.correo,
        cs.cluster_id, cs.segment_name, cs.distance_to_centroid, cs.recency_days,
        cs.orders_180d, cs.spend_180d, cs.avg_ticket_180d, cs.units_180d,
        cs.product_diversity_180d, cs.return_rate, cs.profile_summary,
        cs.suggested_action, cs.generated_at
      FROM customer_segments cs INNER JOIN users u ON u.id = cs.user_id
      WHERE ${conditions.join(' AND ')}
      ORDER BY FIELD(cs.segment_name,'Alto valor','Frecuente','Ocasional','En riesgo'), cs.distance_to_centroid, u.id
      LIMIT ${limit}
    `, params);
    const [summaryRows] = await db.execute(`SELECT segment_name, COUNT(*) AS total FROM customer_segments GROUP BY segment_name`);
    const [[model]] = await db.execute(`SELECT algorithm, metrics_json, dataset_rows, trained_at FROM ml_models WHERE name='customer_segments'`);
    const summary = { total:0, segments:{} };
    summaryRows.forEach(item => { summary.segments[item.segment_name] = Number(item.total); summary.total += Number(item.total); });
    res.json({
      customers: customers.map(item => ({ ...item, distance_to_centroid:Number(item.distance_to_centroid), spend_180d:Number(item.spend_180d), avg_ticket_180d:Number(item.avg_ticket_180d), return_rate:Number(item.return_rate) })),
      summary,
      model: model ? { algorithm:model.algorithm, metrics:JSON.parse(model.metrics_json || '{}'), datasetRows:Number(model.dataset_rows), trainedAt:model.trained_at } : null,
    });
  } catch (error) {
    console.error('Error consultando segmentos:', error.message);
    res.status(500).json({ error:'No se pudieron consultar los segmentos de clientes' });
  }
});

module.exports = router;
