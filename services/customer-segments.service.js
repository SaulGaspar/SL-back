const DAY_MS = 24 * 60 * 60 * 1000;
const FEATURE_NAMES = [
  'recencia_dias', 'pedidos_180d', 'gasto_180d', 'ticket_promedio_180d',
  'unidades_180d', 'diversidad_productos_180d', 'tasa_devolucion',
];

function createRandom(seed) {
  let state = seed >>> 0;
  return () => {
    state = (1664525 * state + 1013904223) >>> 0;
    return state / 4294967296;
  };
}

const distanceSquared = (a, b) => a.reduce((sum, value, index) => sum + (value - b[index]) ** 2, 0);
const distance = (a, b) => Math.sqrt(distanceSquared(a, b));

function standardize(rows) {
  const means = FEATURE_NAMES.map((_, feature) => rows.reduce((sum, row) => sum + row.x[feature], 0) / rows.length);
  const deviations = FEATURE_NAMES.map((_, feature) => {
    const variance = rows.reduce((sum, row) => sum + (row.x[feature] - means[feature]) ** 2, 0) / rows.length;
    return Math.sqrt(variance) || 1;
  });
  return {
    means,
    deviations,
    points: rows.map(row => row.x.map((value, feature) => (value - means[feature]) / deviations[feature])),
  };
}

function initializeCentroids(points, k, random) {
  const centroids = [[...points[Math.floor(random() * points.length)]]];
  while (centroids.length < k) {
    const weights = points.map(point => Math.min(...centroids.map(centroid => distanceSquared(point, centroid))));
    const total = weights.reduce((sum, value) => sum + value, 0);
    if (!total) {
      centroids.push([...points[Math.floor(random() * points.length)]]);
      continue;
    }
    let target = random() * total;
    let selected = points.length - 1;
    for (let index = 0; index < weights.length; index += 1) {
      target -= weights[index];
      if (target <= 0) { selected = index; break; }
    }
    centroids.push([...points[selected]]);
  }
  return centroids;
}

function runKMeans(points, k, seed) {
  const random = createRandom(seed);
  let centroids = initializeCentroids(points, k, random);
  let assignments = new Array(points.length).fill(-1);

  for (let iteration = 0; iteration < 100; iteration += 1) {
    const nextAssignments = points.map(point => {
      let best = 0;
      let bestDistance = Infinity;
      centroids.forEach((centroid, cluster) => {
        const current = distanceSquared(point, centroid);
        if (current < bestDistance) { bestDistance = current; best = cluster; }
      });
      return best;
    });
    const unchanged = nextAssignments.every((cluster, index) => cluster === assignments[index]);
    assignments = nextAssignments;
    if (unchanged) break;

    centroids = Array.from({ length: k }, (_, cluster) => {
      const members = points.filter((_, index) => assignments[index] === cluster);
      if (!members.length) return [...points[Math.floor(random() * points.length)]];
      return FEATURE_NAMES.map((_, feature) => members.reduce((sum, point) => sum + point[feature], 0) / members.length);
    });
  }

  const inertia = points.reduce((sum, point, index) => sum + distanceSquared(point, centroids[assignments[index]]), 0);
  return { centroids, assignments, inertia };
}

function trainKMeans(points, k = 4) {
  let best = null;
  for (let restart = 0; restart < 12; restart += 1) {
    const result = runKMeans(points, k, 20260720 + restart * 997);
    if (!best || result.inertia < best.inertia) best = result;
  }
  return best;
}

function silhouetteScore(points, assignments, k) {
  const selected = points.length <= 500
    ? points.map((_, index) => index)
    : Array.from({ length: 500 }, (_, index) => Math.floor(index * points.length / 500));
  let totalScore = 0;
  for (const index of selected) {
    const own = assignments[index];
    const sums = new Array(k).fill(0);
    const counts = new Array(k).fill(0);
    for (let other = 0; other < points.length; other += 1) {
      if (other === index) continue;
      const cluster = assignments[other];
      sums[cluster] += distance(points[index], points[other]);
      counts[cluster] += 1;
    }
    const a = counts[own] ? sums[own] / counts[own] : 0;
    let b = Infinity;
    for (let cluster = 0; cluster < k; cluster += 1) {
      if (cluster !== own && counts[cluster]) b = Math.min(b, sums[cluster] / counts[cluster]);
    }
    totalScore += Math.max(a, b) ? (b - a) / Math.max(a, b) : 0;
  }
  return totalScore / selected.length;
}

function assignSegmentNames(centroids) {
  const available = new Set(centroids.map((_, index) => index));
  const choose = score => {
    let selected = [...available][0];
    for (const cluster of available) if (score(centroids[cluster]) > score(centroids[selected])) selected = cluster;
    available.delete(selected);
    return selected;
  };
  const mapping = {};
  mapping[choose(center => center[2] + center[3] * 0.7 + center[1] * 0.4)] = 'Alto valor';
  mapping[choose(center => center[0] - center[1] * 0.35)] = 'En riesgo';
  mapping[choose(center => center[1] + center[4] * 0.5 - center[0] * 0.25)] = 'Frecuente';
  mapping[[...available][0]] = 'Ocasional';
  return mapping;
}

const ACTIONS = {
  'Alto valor': 'Ofrecer beneficios VIP y acceso anticipado a promociones.',
  'Frecuente': 'Aplicar fidelización y recomendaciones complementarias.',
  'Ocasional': 'Enviar un incentivo relevante para impulsar la siguiente compra.',
  'En riesgo': 'Iniciar una campaña de recuperación con oferta personalizada.',
};

function profileSummary(segment, x) {
  const [recency, orders, spend, ticket, units, diversity, returnRate] = x;
  if (segment === 'Alto valor') return `${orders} pedidos y $${Math.round(spend).toLocaleString('es-MX')} gastados en 180 días`;
  if (segment === 'Frecuente') return `${orders} pedidos, ${units} unidades y compra hace ${recency} días`;
  if (segment === 'En riesgo') return `Última compra hace ${recency} días; ticket promedio $${Math.round(ticket).toLocaleString('es-MX')}`;
  return `${orders} pedido(s), ${diversity} producto(s) distintos y ${Math.round(returnRate * 100)}% de devolución`;
}

async function loadCustomerRows(db, cutoff = new Date()) {
  const [orders] = await db.execute(`
    SELECT o.id, o.user_id, o.fecha, o.total,
      COALESCE(SUM(oi.cantidad), 0) AS unidades,
      GROUP_CONCAT(DISTINCT oi.product_id ORDER BY oi.product_id) AS productos
    FROM orders o
    LEFT JOIN order_items oi ON oi.order_id = o.id
    WHERE o.status = 'entregado'
    GROUP BY o.id, o.user_id, o.fecha, o.total
    ORDER BY o.user_id, o.fecha
  `);
  const [returns] = await db.execute(`SELECT user_id, COUNT(*) AS total FROM return_requests WHERE created_at <= ? GROUP BY user_id`, [cutoff]);
  const returnCounts = new Map(returns.map(item => [Number(item.user_id), Number(item.total)]));
  const grouped = new Map();
  for (const order of orders) {
    const userId = Number(order.user_id);
    if (!grouped.has(userId)) grouped.set(userId, []);
    grouped.get(userId).push({
      fecha: new Date(order.fecha), total: Number(order.total), unidades: Number(order.unidades),
      productos: String(order.productos || '').split(',').filter(Boolean).map(Number),
    });
  }

  const start = new Date(cutoff.getTime() - 180 * DAY_MS);
  const rows = [];
  for (const [userId, userOrders] of grouped) {
    const prior = userOrders.filter(order => order.fecha <= cutoff);
    if (!prior.length) continue;
    const recent = prior.filter(order => order.fecha > start);
    const spend = recent.reduce((sum, order) => sum + order.total, 0);
    const units = recent.reduce((sum, order) => sum + order.unidades, 0);
    const diversity = new Set(recent.flatMap(order => order.productos)).size;
    const returnsCount = returnCounts.get(userId) || 0;
    rows.push({ userId, x: [
      Math.max(0, Math.round((cutoff - prior[prior.length - 1].fecha) / DAY_MS)),
      recent.length,
      Number(spend.toFixed(2)),
      Number((spend / Math.max(recent.length, 1)).toFixed(2)),
      units,
      diversity,
      Number((returnsCount / prior.length).toFixed(4)),
    ] });
  }
  return rows;
}

async function ensureTables(db) {
  await db.execute(`
    CREATE TABLE IF NOT EXISTS ml_models (
      name VARCHAR(64) NOT NULL PRIMARY KEY, algorithm VARCHAR(80) NOT NULL,
      feature_names LONGTEXT NOT NULL, model_json LONGTEXT NOT NULL,
      metrics_json LONGTEXT NOT NULL, dataset_rows INT NOT NULL,
      positive_rate DECIMAL(10, 8) NOT NULL, trained_at DATETIME NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);
  await db.execute(`
    CREATE TABLE IF NOT EXISTS customer_segments (
      user_id INT NOT NULL PRIMARY KEY, cluster_id INT NOT NULL,
      segment_name VARCHAR(40) NOT NULL, distance_to_centroid DECIMAL(12, 8) NOT NULL,
      recency_days INT NOT NULL, orders_180d INT NOT NULL, spend_180d DECIMAL(12, 2) NOT NULL,
      avg_ticket_180d DECIMAL(12, 2) NOT NULL, units_180d INT NOT NULL,
      product_diversity_180d INT NOT NULL, return_rate DECIMAL(10, 6) NOT NULL,
      profile_summary VARCHAR(255) NOT NULL, suggested_action VARCHAR(255) NOT NULL,
      generated_at DATETIME NOT NULL,
      INDEX idx_customer_segment (segment_name, distance_to_centroid)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);
}

async function buildCustomerSegments(db) {
  const generatedAt = new Date();
  const rows = await loadCustomerRows(db, generatedAt);
  if (rows.length < 20) throw new Error('No hay suficientes clientes con compras para generar segmentos');
  const standardized = standardize(rows);
  const trained = trainKMeans(standardized.points, 4);
  const names = assignSegmentNames(trained.centroids);
  const silhouette = silhouetteScore(standardized.points, trained.assignments, 4);
  const results = rows.map((row, index) => {
    const cluster = trained.assignments[index];
    const segment = names[cluster];
    return {
      ...row, cluster, segment,
      distance: distance(standardized.points[index], trained.centroids[cluster]),
      profile: profileSummary(segment, row.x), action: ACTIONS[segment],
    };
  });
  const model = { algorithm:'K-Means', k:4, featureNames:FEATURE_NAMES, means:standardized.means, deviations:standardized.deviations, centroids:trained.centroids, segmentNames:names };
  const metrics = { inertia:trained.inertia, silhouette, iterationsMax:100, restarts:12 };

  const connection = typeof db.getConnection === 'function' ? await db.getConnection() : db;
  try {
    await ensureTables(connection);
    await connection.beginTransaction();
    await connection.execute(`
      INSERT INTO ml_models (name, algorithm, feature_names, model_json, metrics_json, dataset_rows, positive_rate, trained_at)
      VALUES ('customer_segments', 'K-Means', ?, ?, ?, ?, 0, ?)
      ON DUPLICATE KEY UPDATE algorithm=VALUES(algorithm), feature_names=VALUES(feature_names), model_json=VALUES(model_json),
        metrics_json=VALUES(metrics_json), dataset_rows=VALUES(dataset_rows), trained_at=VALUES(trained_at)
    `, [JSON.stringify(FEATURE_NAMES), JSON.stringify(model), JSON.stringify(metrics), rows.length, generatedAt]);
    await connection.execute('DELETE FROM customer_segments');
    for (let index = 0; index < results.length; index += 250) {
      const values = results.slice(index, index + 250).map(item => [
        item.userId, item.cluster, item.segment, item.distance,
        item.x[0], item.x[1], item.x[2], item.x[3], item.x[4], item.x[5], item.x[6],
        item.profile, item.action, generatedAt,
      ]);
      await connection.query(`
        INSERT INTO customer_segments (
          user_id, cluster_id, segment_name, distance_to_centroid, recency_days,
          orders_180d, spend_180d, avg_ticket_180d, units_180d,
          product_diversity_180d, return_rate, profile_summary, suggested_action, generated_at
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

  const counts = results.reduce((summary, item) => ({ ...summary, [item.segment]:(summary[item.segment] || 0) + 1 }), {});
  return { rows:rows.length, counts, metrics, generatedAt };
}

module.exports = { FEATURE_NAMES, buildCustomerSegments };
