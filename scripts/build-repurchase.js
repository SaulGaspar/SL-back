require('dotenv').config();

const { getDB } = require('../config/db');
const { buildRepurchaseModel } = require('../services/repurchase.service');

(async () => {
  const db = await getDB();
  try {
    const result = await buildRepurchaseModel(db);
    console.log('Modelo de recompra entrenado y predicciones generadas.');
    console.table({
      filas_dataset: result.datasetRows,
      tasa_recompra: Number(result.positiveRate.toFixed(4)),
      clientes_clasificados: result.predictions,
      exactitud_validacion: Number(result.metrics.accuracy.toFixed(4)),
      precision_validacion: Number(result.metrics.precision.toFixed(4)),
      sensibilidad_validacion: Number(result.metrics.recall.toFixed(4)),
      f1_validacion: Number(result.metrics.f1.toFixed(4)),
      umbral_campana: result.metrics.campaign.threshold,
      sensibilidad_campana: Number(result.metrics.campaign.recall.toFixed(4)),
      f1_campana: Number(result.metrics.campaign.f1.toFixed(4)),
    });
  } finally {
    if (typeof db.end === 'function') await db.end();
  }
})().catch(error => {
  console.error('No se pudo generar el modelo de recompra:', error.message);
  process.exitCode = 1;
});
