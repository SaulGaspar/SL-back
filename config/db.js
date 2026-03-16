const mysql = require('mysql2/promise');

// ─────────────────────────────────────────────────────────────
// Pool singleton — se crea UNA sola vez y se reutiliza en todas
// las llamadas. En Vercel serverless esto reduce las conexiones
// abiertas de ~50 a 3-5 máximo.
// ─────────────────────────────────────────────────────────────
let pool = null;

function getPool() {
  if (pool) return pool;          // ya existe → reutilizar

  pool = mysql.createPool({
    host:     process.env.DB_HOST,
    user:     process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    port:     Number(process.env.DB_PORT) || 3306,

    // SSL requerido por Aiven
    ssl: { rejectUnauthorized: false },

    // ── Límites de conexión ───────────────────────────────────
    connectionLimit:    3,     // máximo 3 conexiones simultáneas
                               // (era 10 → multiplicado por cada
                               //  invocación serverless = overflow)
    waitForConnections: true,  // pone en cola en lugar de lanzar error
    queueLimit:         10,    // máximo 10 requests esperando

    // ── Timeouts ─────────────────────────────────────────────
    connectTimeout:          10_000,   // 10s para conectar
    idleTimeout:             30_000,   // cierra conexiones inactivas a los 30s
    enableKeepAlive:         true,
    keepAliveInitialDelay:   10_000,
  });

  // Log solo en desarrollo
  if (process.env.NODE_ENV !== 'production') {
    console.log('🟢 MySQL pool creado (connectionLimit: 3)');
  }

  return pool;
}

// getDB devuelve siempre el mismo pool — compatible con todo el código existente
async function getDB() {
  return getPool();
}

module.exports = { getDB };