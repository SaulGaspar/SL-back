require('dotenv').config();

const { getDB } = require('../config/db');
const { buildAprioriRules, DEFAULTS } = require('../services/apriori.service');

async function main() {
  const db = await getDB();
  try {
    const result = await buildAprioriRules({
      db,
      minSupport: process.env.APRIORI_MIN_SUPPORT || DEFAULTS.minSupport,
      minConfidence: process.env.APRIORI_MIN_CONFIDENCE || DEFAULTS.minConfidence,
      minLift: process.env.APRIORI_MIN_LIFT || DEFAULTS.minLift,
    });
    console.log('Reglas de recomendación Apriori generadas correctamente.');
    console.table({
      transacciones_analizadas: result.transactions,
      productos_analizados: result.products,
      reglas_generadas: result.rules,
      soporte_minimo: result.thresholds.minSupport,
      confianza_minima: result.thresholds.minConfidence,
      lift_minimo: result.thresholds.minLift,
    });
  } finally {
    if (typeof db.end === 'function') await db.end();
  }
}

main().catch(error => {
  console.error('No se pudieron generar las reglas Apriori:', error.message);
  process.exitCode = 1;
});
