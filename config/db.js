const mysql = require('mysql2/promise');


let pool = null;

function getPool() {
  if (pool) return pool;        

  pool = mysql.createPool({
    host:     process.env.DB_HOST,
    user:     process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    port:     Number(process.env.DB_PORT) || 3306,

    ssl: { rejectUnauthorized: false },

    // ── Límites de conexión
    connectionLimit:    3,   
    waitForConnections: true,  
    queueLimit:         10,   

    // ── Timeouts 
    connectTimeout:          10_000,  
    idleTimeout:             30_000,   
    enableKeepAlive:         true,
    keepAliveInitialDelay:   10_000,
  });

  if (process.env.NODE_ENV !== 'production') {
    console.log('🟢 MySQL pool creado (connectionLimit: 3)');
  }

  return pool;
}

async function getDB() {
  return getPool();
}

module.exports = { getDB };