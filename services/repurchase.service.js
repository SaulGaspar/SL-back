const DAY_MS = 24 * 60 * 60 * 1000;
const FEATURE_NAMES = [
  'recencia_dias',
  'pedidos_90d',
  'gasto_90d',
  'ticket_promedio_90d',
  'unidades_90d',
  'diversidad_productos_90d',
  'devoluciones_previas',
];

const addDays = (date, days) => new Date(date.getTime() + days * DAY_MS);
const asDate = value => value instanceof Date ? value : new Date(value);
const isoDate = date => date.toISOString().slice(0, 10);

function createRandom(seed = 20260720) {
  let state = seed >>> 0;
  return () => {
    state = (1664525 * state + 1013904223) >>> 0;
    return state / 4294967296;
  };
}

function gini(positives, total) {
  if (!total) return 0;
  const p = positives / total;
  return 1 - p * p - (1 - p) * (1 - p);
}

function sampleFeatures(total, count, random) {
  const features = Array.from({ length: total }, (_, index) => index);
  for (let i = features.length - 1; i > 0; i -= 1) {
    const j = Math.floor(random() * (i + 1));
    [features[i], features[j]] = [features[j], features[i]];
  }
  return features.slice(0, count);
}

function findBestSplit(samples, indices, random, minLeaf) {
  const parentPositives = indices.reduce((sum, index) => sum + samples[index].y, 0);
  const parentImpurity = gini(parentPositives, indices.length);
  let best = null;

  for (const feature of sampleFeatures(FEATURE_NAMES.length, 3, random)) {
    const sortedValues = [...new Set(indices.map(index => samples[index].x[feature]))].sort((a, b) => a - b);
    if (sortedValues.length < 2) continue;

    const thresholds = [];
    const candidateCount = Math.min(12, sortedValues.length - 1);
    for (let candidate = 1; candidate <= candidateCount; candidate += 1) {
      const position = Math.min(
        Math.floor(candidate * sortedValues.length / (candidateCount + 1)),
        sortedValues.length - 1
      );
      const previous = sortedValues[Math.max(0, position - 1)];
      const current = sortedValues[position];
      if (previous !== current) thresholds.push((previous + current) / 2);
    }

    for (const threshold of [...new Set(thresholds)]) {
      let leftTotal = 0;
      let leftPositives = 0;
      for (const index of indices) {
        if (samples[index].x[feature] <= threshold) {
          leftTotal += 1;
          leftPositives += samples[index].y;
        }
      }
      const rightTotal = indices.length - leftTotal;
      if (leftTotal < minLeaf || rightTotal < minLeaf) continue;
      const rightPositives = parentPositives - leftPositives;
      const impurity = (leftTotal * gini(leftPositives, leftTotal) + rightTotal * gini(rightPositives, rightTotal)) / indices.length;
      const gain = parentImpurity - impurity;
      if (!best || gain > best.gain) best = { feature, threshold, gain };
    }
  }
  return best && best.gain > 0.00001 ? best : null;
}

function buildTree(samples, indices, random, depth, options) {
  const positives = indices.reduce((sum, index) => sum + samples[index].y, 0);
  const probability = (positives + 1) / (indices.length + 2);
  if (depth >= options.maxDepth || indices.length < options.minSamplesSplit || positives === 0 || positives === indices.length) {
    return { p: probability, n: indices.length };
  }

  const split = findBestSplit(samples, indices, random, options.minLeaf);
  if (!split) return { p: probability, n: indices.length };
  const left = [];
  const right = [];
  for (const index of indices) {
    (samples[index].x[split.feature] <= split.threshold ? left : right).push(index);
  }
  return {
    f: split.feature,
    t: split.threshold,
    g: split.gain,
    l: buildTree(samples, left, random, depth + 1, options),
    r: buildTree(samples, right, random, depth + 1, options),
  };
}

function trainForest(samples, { trees = 56, seed = 20260720 } = {}) {
  const random = createRandom(seed);
  const options = { maxDepth: 7, minSamplesSplit: 28, minLeaf: 10 };
  const forest = [];
  for (let treeIndex = 0; treeIndex < trees; treeIndex += 1) {
    const bootstrap = Array.from({ length: samples.length }, () => Math.floor(random() * samples.length));
    forest.push(buildTree(samples, bootstrap, random, 0, options));
  }
  const baselines = FEATURE_NAMES.map((_, feature) => {
    const values = samples.map(sample => sample.x[feature]).sort((a, b) => a - b);
    return values[Math.floor(values.length / 2)] || 0;
  });
  return { algorithm: 'Random Forest', featureNames: FEATURE_NAMES, trees: forest, options, baselines, seed };
}

function predictTree(tree, features) {
  let node = tree;
  while (node.f !== undefined) node = features[node.f] <= node.t ? node.l : node.r;
  return node.p;
}

function predictProbability(model, features) {
  return model.trees.reduce((sum, tree) => sum + predictTree(tree, features), 0) / model.trees.length;
}

function evaluate(model, samples, threshold = 0.5) {
  let tp = 0; let tn = 0; let fp = 0; let fn = 0;
  for (const sample of samples) {
    const predicted = predictProbability(model, sample.x) >= threshold ? 1 : 0;
    if (predicted && sample.y) tp += 1;
    else if (predicted && !sample.y) fp += 1;
    else if (!predicted && sample.y) fn += 1;
    else tn += 1;
  }
  const accuracy = (tp + tn) / Math.max(samples.length, 1);
  const precision = tp / Math.max(tp + fp, 1);
  const recall = tp / Math.max(tp + fn, 1);
  const f1 = 2 * precision * recall / Math.max(precision + recall, Number.EPSILON);
  return { accuracy, precision, recall, f1, threshold, validationRows: samples.length, confusionMatrix: { tp, tn, fp, fn } };
}

function selectDecisionThreshold(model, samples) {
  let best = evaluate(model, samples, 0.5);
  for (let threshold = 0.2; threshold <= 0.6; threshold += 0.025) {
    const candidate = evaluate(model, samples, Number(threshold.toFixed(3)));
    if (candidate.f1 > best.f1) best = candidate;
  }
  return best;
}

async function loadSourceData(db) {
  const [orders] = await db.execute(`
    SELECT o.id, o.user_id, o.fecha, o.total,
      COALESCE(SUM(oi.cantidad), 0) AS unidades,
      GROUP_CONCAT(DISTINCT oi.product_id ORDER BY oi.product_id) AS productos
    FROM orders o
    LEFT JOIN order_items oi ON oi.order_id = o.id
    WHERE o.status = 'entregado'
    GROUP BY o.id, o.user_id, o.fecha, o.total
    ORDER BY o.fecha, o.id
  `);
  const [returns] = await db.execute(`SELECT user_id, created_at FROM return_requests ORDER BY created_at`);
  return {
    orders: orders.map(order => ({
      ...order,
      fecha: asDate(order.fecha),
      total: Number(order.total),
      unidades: Number(order.unidades),
      productos: String(order.productos || '').split(',').filter(Boolean).map(Number),
    })),
    returns: returns.map(item => ({ userId: Number(item.user_id), fecha: asDate(item.created_at) })),
  };
}

function featuresAt(userOrders, userReturns, cutoff) {
  const prior = userOrders.filter(order => order.fecha <= cutoff);
  if (!prior.length) return null;
  const start = addDays(cutoff, -90);
  const recent = prior.filter(order => order.fecha > start);
  const latest = prior[prior.length - 1];
  const spend = recent.reduce((sum, order) => sum + order.total, 0);
  const units = recent.reduce((sum, order) => sum + order.unidades, 0);
  const products = new Set(recent.flatMap(order => order.productos));
  return [
    Math.max(0, Math.round((cutoff - latest.fecha) / DAY_MS)),
    recent.length,
    Number(spend.toFixed(2)),
    Number((spend / Math.max(recent.length, 1)).toFixed(2)),
    units,
    products.size,
    userReturns.filter(item => item.fecha <= cutoff).length,
  ];
}

function groupByUser(items, key = 'user_id') {
  const grouped = new Map();
  for (const item of items) {
    const userId = Number(item[key]);
    if (!grouped.has(userId)) grouped.set(userId, []);
    grouped.get(userId).push(item);
  }
  return grouped;
}

function createTrainingDataset(source) {
  const byUser = groupByUser(source.orders);
  const returnsByUser = groupByUser(source.returns, 'userId');
  const minDate = source.orders[0].fecha;
  const maxDate = source.orders[source.orders.length - 1].fecha;
  const firstCutoff = new Date(minDate.getFullYear(), minDate.getMonth() + 3, 1);
  const lastCutoff = addDays(maxDate, -30);
  const samples = [];

  for (let cutoff = firstCutoff; cutoff <= lastCutoff; cutoff = new Date(cutoff.getFullYear(), cutoff.getMonth() + 1, 1)) {
    const futureLimit = addDays(cutoff, 30);
    for (const [userId, orders] of byUser) {
      const x = featuresAt(orders, returnsByUser.get(userId) || [], cutoff);
      if (!x) continue;
      const y = orders.some(order => order.fecha > cutoff && order.fecha <= futureLimit) ? 1 : 0;
      samples.push({ userId, cutoff: isoDate(cutoff), x, y });
    }
  }
  return samples;
}

function primaryFactor(model, features) {
  const [recency, orders, spend, ticket, units, diversity, returns] = features;
  const currentProbability = predictProbability(model, features);
  let bestFeature = 0;
  let bestImpact = -1;
  for (let feature = 0; feature < features.length; feature += 1) {
    const adjusted = [...features];
    adjusted[feature] = model.baselines[feature];
    const impact = Math.abs(currentProbability - predictProbability(model, adjusted));
    if (impact > bestImpact) { bestImpact = impact; bestFeature = feature; }
  }
  const labels = [
    `Última compra: hace ${recency} días`,
    `${orders} pedido(s) en 90 días`,
    `Gasto reciente: $${Math.round(spend).toLocaleString('es-MX')}`,
    `Ticket promedio: $${Math.round(ticket).toLocaleString('es-MX')}`,
    `${units} unidad(es) en 90 días`,
    `Diversidad: ${diversity} producto(s)`,
    `${returns} devolución(es) previa(s)`,
  ];
  return labels[bestFeature];
}

function levelFor(probability) {
  if (probability >= 0.55) return 'alta';
  if (probability >= 0.30) return 'media';
  return 'baja';
}

async function ensureTables(db) {
  await db.execute(`
    CREATE TABLE IF NOT EXISTS ml_models (
      name VARCHAR(64) NOT NULL PRIMARY KEY,
      algorithm VARCHAR(80) NOT NULL,
      feature_names LONGTEXT NOT NULL,
      model_json LONGTEXT NOT NULL,
      metrics_json LONGTEXT NOT NULL,
      dataset_rows INT NOT NULL,
      positive_rate DECIMAL(10, 8) NOT NULL,
      trained_at DATETIME NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);
  await db.execute(`
    CREATE TABLE IF NOT EXISTS repurchase_predictions (
      user_id INT NOT NULL PRIMARY KEY,
      probability DECIMAL(10, 8) NOT NULL,
      level ENUM('alta','media','baja') NOT NULL,
      recency_days INT NOT NULL,
      orders_90d INT NOT NULL,
      spend_90d DECIMAL(12, 2) NOT NULL,
      avg_ticket_90d DECIMAL(12, 2) NOT NULL,
      units_90d INT NOT NULL,
      product_diversity_90d INT NOT NULL,
      previous_returns INT NOT NULL,
      primary_factor VARCHAR(255) NOT NULL,
      generated_at DATETIME NOT NULL,
      INDEX idx_repurchase_level_probability (level, probability)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);
}

async function buildRepurchaseModel(db) {
  const source = await loadSourceData(db);
  if (!source.orders.length) throw new Error('No hay pedidos entregados para entrenar el modelo');
  const dataset = createTrainingDataset(source);
  const training = dataset.filter((_, index) => index % 5 !== 0);
  const validation = dataset.filter((_, index) => index % 5 === 0);
  const model = trainForest(training);
  const campaignMetrics = selectDecisionThreshold(model, validation);
  const metrics = { ...evaluate(model, validation, 0.5), campaign: campaignMetrics };
  model.decisionThreshold = campaignMetrics.threshold;
  const positiveRate = dataset.reduce((sum, row) => sum + row.y, 0) / dataset.length;

  const byUser = groupByUser(source.orders);
  const returnsByUser = groupByUser(source.returns, 'userId');
  const predictionDate = new Date();
  const predictions = [];
  for (const [userId, orders] of byUser) {
    const features = featuresAt(orders, returnsByUser.get(userId) || [], predictionDate);
    if (!features) continue;
    const probability = predictProbability(model, features);
    predictions.push({ userId, probability, level: levelFor(probability), features, primaryFactor: primaryFactor(model, features) });
  }

  const connection = typeof db.getConnection === 'function' ? await db.getConnection() : db;
  const trainedAt = new Date();
  try {
    await ensureTables(connection);
    await connection.beginTransaction();
    await connection.execute(`
      INSERT INTO ml_models (name, algorithm, feature_names, model_json, metrics_json, dataset_rows, positive_rate, trained_at)
      VALUES ('repurchase_30d', ?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE algorithm=VALUES(algorithm), feature_names=VALUES(feature_names),
        model_json=VALUES(model_json), metrics_json=VALUES(metrics_json), dataset_rows=VALUES(dataset_rows),
        positive_rate=VALUES(positive_rate), trained_at=VALUES(trained_at)
    `, [model.algorithm, JSON.stringify(FEATURE_NAMES), JSON.stringify(model), JSON.stringify(metrics), dataset.length, positiveRate, trainedAt]);
    await connection.execute('DELETE FROM repurchase_predictions');
    for (let index = 0; index < predictions.length; index += 250) {
      const values = predictions.slice(index, index + 250).map(item => [
        item.userId, item.probability, item.level,
        item.features[0], item.features[1], item.features[2], item.features[3],
        item.features[4], item.features[5], item.features[6], item.primaryFactor, trainedAt,
      ]);
      await connection.query(`
        INSERT INTO repurchase_predictions (
          user_id, probability, level, recency_days, orders_90d, spend_90d,
          avg_ticket_90d, units_90d, product_diversity_90d, previous_returns,
          primary_factor, generated_at
        ) VALUES ?
      `, [values]);
    }
    await connection.commit();
  } catch (error) {
    try { await connection.rollback(); } catch (_) {}
    throw error;
  } finally {
    if (connection !== db && typeof connection.release === 'function') connection.release();
  }

  return { datasetRows: dataset.length, positiveRate, predictions: predictions.length, metrics, trainedAt };
}

module.exports = { FEATURE_NAMES, buildRepurchaseModel };
