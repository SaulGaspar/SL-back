function invalidFilter(message) {
  const error = new Error(message); error.statusCode = 400; return error;
}

function validDate(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const date = new Date(value+'T00:00:00Z');
  return Number.isFinite(date.getTime()) && date.toISOString().slice(0,10) === value;
}

function buildOrderFilter(query = {}) {
  const { from, to } = query;
  const branch = query.branch ?? query.sucursal;
  if ((from && !validDate(from)) || (to && !validDate(to))) throw invalidFilter('Selecciona fechas válidas.');
  if (from && to && from > to) throw invalidFilter('La fecha inicial no puede ser posterior a la final.');
  const conditions = ['1=1'], params = [];
  if (from) { conditions.push('o.fecha >= ?'); params.push(from); }
  // Límite exclusivo del día siguiente: incluye todo el día final y sus fracciones de segundo.
  if (to) { conditions.push('o.fecha < DATE_ADD(?, INTERVAL 1 DAY)'); params.push(to); }
  if (branch && branch !== 'all') {
    if (typeof branch !== 'string' || !/^[1-9]\d*$/.test(branch) || !Number.isSafeInteger(Number(branch))) throw invalidFilter('Selecciona una sucursal válida.');
    conditions.push('o.sucursal = ?'); params.push(Number(branch));
  }
  return { where:'WHERE '+conditions.join(' AND '), params };
}

function orderSummarySQL(where) {
  return `SELECT COUNT(*) AS total_ordenes,
    COALESCE(SUM(CASE WHEN o.status <> 'cancelado' THEN o.total ELSE 0 END),0) AS ingresos_totales,
    COALESCE(AVG(CASE WHEN o.status <> 'cancelado' THEN o.total END),0) AS ticket_promedio,
    COALESCE(SUM(o.status = 'pendiente'),0) AS pendientes,
    COALESCE(SUM(o.status IN ('preparando','procesando')),0) AS preparando,
    COALESCE(SUM(o.status IN ('en_camino','enviado')),0) AS en_camino,
    COALESCE(SUM(o.status = 'entregado'),0) AS entregadas,
    COALESCE(SUM(o.status = 'cancelado'),0) AS canceladas
    FROM orders o ${where}`;
}

function withLegacyAliases(summary = {}) {
  return {...summary, procesando:summary.preparando ?? 0, enviado:summary.en_camino ?? 0};
}

function normalizeOrderStatus(status) {
  return status === 'procesando' ? 'preparando' : status === 'enviado' ? 'en_camino' : status;
}

module.exports = { buildOrderFilter, orderSummarySQL, withLegacyAliases, normalizeOrderStatus };
