const DEFAULTS = Object.freeze({ minSupport: 0.003, minConfidence: 0.15, minLift: 1.10 });

async function ensureAprioriTable(db) {
  await db.execute(`
    CREATE TABLE IF NOT EXISTS apriori_rules (
      id BIGINT NOT NULL AUTO_INCREMENT,
      antecedent_product_id INT NOT NULL,
      consequent_product_id INT NOT NULL,
      support DECIMAL(10, 8) NOT NULL,
      confidence DECIMAL(10, 8) NOT NULL,
      lift DECIMAL(10, 6) NOT NULL,
      pair_count INT NOT NULL,
      antecedent_count INT NOT NULL,
      transaction_count INT NOT NULL,
      generated_at DATETIME NOT NULL,
      PRIMARY KEY (id),
      UNIQUE KEY uq_apriori_direction (antecedent_product_id, consequent_product_id),
      INDEX idx_apriori_antecedent (antecedent_product_id),
      INDEX idx_apriori_ranking (antecedent_product_id, lift, confidence)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);
}

function validNumber(value, fallback) {
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? number : fallback;
}

function calculateRules(transactions, thresholds) {
  const itemCounts = new Map();
  const pairCounts = new Map();

  for (const transaction of transactions) {
    const items = [...new Set(transaction)].sort((a, b) => a - b);
    for (const productId of items) itemCounts.set(productId, (itemCounts.get(productId) || 0) + 1);

    for (let i = 0; i < items.length; i += 1) {
      for (let j = i + 1; j < items.length; j += 1) {
        const key = `${items[i]}:${items[j]}`;
        pairCounts.set(key, (pairCounts.get(key) || 0) + 1);
      }
    }
  }

  const total = transactions.length;
  const rules = [];
  for (const [key, pairCount] of pairCounts) {
    const [first, second] = key.split(':').map(Number);
    const support = pairCount / total;
    if (support < thresholds.minSupport) continue;

    for (const [antecedent, consequent] of [[first, second], [second, first]]) {
      const antecedentCount = itemCounts.get(antecedent);
      const confidence = pairCount / antecedentCount;
      const lift = confidence / (itemCounts.get(consequent) / total);
      if (confidence >= thresholds.minConfidence && lift >= thresholds.minLift) {
        rules.push({ antecedent, consequent, support, confidence, lift, pairCount, antecedentCount, transactionCount: total });
      }
    }
  }

  return rules.sort((a, b) => b.lift - a.lift || b.confidence - a.confidence || b.pairCount - a.pairCount);
}

async function buildAprioriRules({ db, minSupport = DEFAULTS.minSupport, minConfidence = DEFAULTS.minConfidence, minLift = DEFAULTS.minLift } = {}) {
  if (!db) throw new Error('Se requiere una conexión a la base de datos');
  const thresholds = {
    minSupport: validNumber(minSupport, DEFAULTS.minSupport),
    minConfidence: validNumber(minConfidence, DEFAULTS.minConfidence),
    minLift: validNumber(minLift, DEFAULTS.minLift),
  };

  const [rows] = await db.execute(`
    SELECT o.id AS order_id, oi.product_id
    FROM orders o
    INNER JOIN order_items oi ON oi.order_id = o.id
    INNER JOIN products p ON p.id = oi.product_id
    WHERE o.status = 'entregado' AND p.activo = 1
    GROUP BY o.id, oi.product_id
    ORDER BY o.id, oi.product_id
  `);

  const grouped = new Map();
  for (const row of rows) {
    if (!grouped.has(row.order_id)) grouped.set(row.order_id, []);
    grouped.get(row.order_id).push(Number(row.product_id));
  }
  const transactions = [...grouped.values()].filter(items => items.length > 0);
  if (!transactions.some(items => new Set(items).size >= 2)) {
    throw new Error('No hay pedidos entregados con al menos dos productos distintos');
  }

  const rules = calculateRules(transactions, thresholds);
  const connection = typeof db.getConnection === 'function' ? await db.getConnection() : db;
  const generatedAt = new Date();

  try {
    await ensureAprioriTable(connection);
    await connection.beginTransaction();
    await connection.execute('DELETE FROM apriori_rules');
    for (let i = 0; i < rules.length; i += 250) {
      const values = rules.slice(i, i + 250).map(rule => [
        rule.antecedent, rule.consequent, rule.support, rule.confidence, rule.lift,
        rule.pairCount, rule.antecedentCount, rule.transactionCount, generatedAt,
      ]);
      await connection.query(`
        INSERT INTO apriori_rules (
          antecedent_product_id, consequent_product_id, support, confidence,
          lift, pair_count, antecedent_count, transaction_count, generated_at
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

  return { transactions: transactions.length, products: new Set(transactions.flat()).size, rules: rules.length, thresholds, generatedAt };
}

async function getRecommendations(db, productId, limit = 4) {
  const safeLimit = Math.min(Math.max(Number(limit) || 4, 1), 12);
  const [rows] = await db.execute(`
    SELECT p.id, p.nombre, p.marca, p.descripcion, p.precio, p.categoria,
      p.imagen, p.talla, p.colores, COALESCE(SUM(i.stock), 0) AS stock_total,
      r.support, r.confidence, r.lift, r.pair_count
    FROM apriori_rules r
    INNER JOIN products p ON p.id = r.consequent_product_id
    LEFT JOIN inventory i ON i.product_id = p.id
    WHERE r.antecedent_product_id = ? AND p.activo = 1
    GROUP BY p.id, p.nombre, p.marca, p.descripcion, p.precio, p.categoria,
      p.imagen, p.talla, p.colores, r.support, r.confidence, r.lift, r.pair_count
    HAVING stock_total > 0
    ORDER BY r.lift DESC, r.confidence DESC, r.pair_count DESC
    LIMIT ${safeLimit}
  `, [productId]);

  return rows.map(row => ({ ...row, precio: Number(row.precio), stock_total: Number(row.stock_total), support: Number(row.support), confidence: Number(row.confidence), lift: Number(row.lift), pair_count: Number(row.pair_count) }));
}

module.exports = { DEFAULTS, buildAprioriRules, getRecommendations };
