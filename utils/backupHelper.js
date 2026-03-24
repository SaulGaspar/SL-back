// utils/backupHelper.js
// Lógica compartida entre el router y el scheduler de backups

// ── Tablas a respaldar (en orden por dependencias FK) ────────────────────────
const TABLAS = [
  'users',
  'branches',
  'products',
  'inventory',
  'orders',
  'order_items',
  'Token',
];

// ── Helper: genera el SQL completo de una tabla ──────────────────────────────
async function generarSQLTabla(db, tabla) {
  let sql = `-- ============================================================\n`;
  sql    += `-- Tabla: ${tabla}\n`;
  sql    += `-- ============================================================\n\n`;

  // Obtener estructura
  try {
    const [cols] = await db.execute(`SHOW CREATE TABLE \`${tabla}\``);
    if (cols.length > 0) {
      const createSQL = cols[0]['Create Table'] || cols[0][`Create Table`];
      sql += `DROP TABLE IF EXISTS \`${tabla}\`;\n`;
      sql += `${createSQL};\n\n`;
    }
  } catch (e) {
    sql += `-- No se pudo obtener estructura de ${tabla}: ${e.message}\n\n`;
    return sql;
  }

  // Obtener datos
  try {
    const [rows] = await db.execute(`SELECT * FROM \`${tabla}\``);

    if (rows.length === 0) {
      sql += `-- Sin registros en ${tabla}\n\n`;
      return sql;
    }

    // Insertar en lotes de 100
    const columns = Object.keys(rows[0]).map(c => `\`${c}\``).join(', ');
    const lotes   = [];

    for (let i = 0; i < rows.length; i += 100) {
      lotes.push(rows.slice(i, i + 100));
    }

    for (const lote of lotes) {
      const values = lote.map(row => {
        const vals = Object.values(row).map(val => {
          if (val === null)             return 'NULL';
          if (typeof val === 'number')  return val;
          if (typeof val === 'boolean') return val ? 1 : 0;
          if (val instanceof Date)      return `'${val.toISOString().slice(0,19).replace('T',' ')}'`;
          const escaped = String(val).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
          return `'${escaped}'`;
        });
        return `(${vals.join(', ')})`;
      }).join(',\n  ');

      sql += `INSERT INTO \`${tabla}\` (${columns}) VALUES\n  ${values};\n\n`;
    }
  } catch (e) {
    sql += `-- No se pudieron exportar datos de ${tabla}: ${e.message}\n\n`;
  }

  return sql;
}

module.exports = { TABLAS, generarSQLTabla };