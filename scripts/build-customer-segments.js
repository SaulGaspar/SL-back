require('dotenv').config();
const { getDB } = require('../config/db');
const { buildCustomerSegments } = require('../services/customer-segments.service');

(async()=>{
  const db = await getDB();
  try {
    const result = await buildCustomerSegments(db);
    console.log('Segmentación de clientes generada correctamente.');
    console.table({ clientes_segmentados:result.rows, ...result.counts, silhouette:Number(result.metrics.silhouette.toFixed(4)), inercia:Number(result.metrics.inertia.toFixed(2)) });
  } finally { if (typeof db.end === 'function') await db.end(); }
})().catch(error=>{ console.error('No se pudo generar la segmentación:', error.message); process.exitCode=1; });
