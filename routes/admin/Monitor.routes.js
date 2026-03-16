const express = require('express');
const router = express.Router();
const { getDB } = require('../../config/db');
const { authMiddleware, adminOnly } = require('../../middlewares/auth');

// ================================
// 📊 GET /api/admin/monitor/overview
// Resumen general de la BD
// ================================
router.get('/overview', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();

    // Tamaño de la BD
    const [dbSize] = await db.execute(`
      SELECT 
        table_schema AS db_name,
        ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS size_mb,
        ROUND(SUM(data_length) / 1024 / 1024, 2) AS data_mb,
        ROUND(SUM(index_length) / 1024 / 1024, 2) AS index_mb
      FROM information_schema.tables
      WHERE table_schema = DATABASE()
      GROUP BY table_schema
    `);

    // Total de tablas
    const [tables] = await db.execute(`
      SELECT COUNT(*) AS total FROM information_schema.tables
      WHERE table_schema = DATABASE()
    `);

    // Variables del servidor MySQL
    const [uptime]      = await db.execute(`SHOW STATUS LIKE 'Uptime'`);
    const [connections] = await db.execute(`SHOW STATUS LIKE 'Threads_connected'`);
    const [maxConn]     = await db.execute(`SHOW VARIABLES LIKE 'max_connections'`);
    const [queries]     = await db.execute(`SHOW STATUS LIKE 'Queries'`);
    const [slowQ]       = await db.execute(`SHOW STATUS LIKE 'Slow_queries'`);
    const [version]     = await db.execute(`SELECT VERSION() AS version`);
    const [charset]     = await db.execute(`SHOW VARIABLES LIKE 'character_set_database'`);

    // Conteos por tabla
    const [rowCounts] = await db.execute(`
      SELECT 
        table_name   AS tname,
        table_rows   AS trows,
        ROUND((data_length + index_length) / 1024, 2) AS size_kb,
        ROUND(data_length / 1024, 2)                  AS data_kb,
        ROUND(index_length / 1024, 2)                 AS index_kb,
        create_time  AS created_at,
        update_time  AS updated_at,
        engine       AS tengine
      FROM information_schema.tables
      WHERE table_schema = DATABASE()
      ORDER BY (data_length + index_length) DESC
    `);

    res.json({
      database: {
        name:     dbSize[0]?.db_name     || 'N/A',
        size_mb:  dbSize[0]?.size_mb     || 0,
        data_mb:  dbSize[0]?.data_mb     || 0,
        index_mb: dbSize[0]?.index_mb    || 0,
        tables:   tables[0]?.total       || 0,
        version:  version[0]?.version    || 'N/A',
        charset:  charset[0]?.Value      || 'N/A',
      },
      server: {
        uptime_seconds:  parseInt(uptime[0]?.Value      || 0),
        connections:     parseInt(connections[0]?.Value || 0),
        max_connections: parseInt(maxConn[0]?.Value     || 0),
        total_queries:   parseInt(queries[0]?.Value     || 0),
        slow_queries:    parseInt(slowQ[0]?.Value       || 0),
      },
      tables: rowCounts.map(t => ({
        name:      t.tname    || t.table_name   || t.TABLE_NAME   || '?',
        rows:      t.trows    || t.table_rows   || t.TABLE_ROWS   || 0,
        size_kb:   t.size_kb  || 0,
        data_kb:   t.data_kb  || 0,
        index_kb:  t.index_kb || 0,
        engine:    t.tengine  || t.engine       || t.ENGINE       || 'N/A',
        created:   t.created_at || t.create_time,
        updated:   t.updated_at || t.update_time,
      })),
    });
  } catch (err) {
    console.error('Error en monitor overview:', err);
    res.status(500).json({ error: 'Error obteniendo métricas de BD' });
  }
});

// ================================
// 📈 GET /api/admin/monitor/activity
// Actividad reciente: pedidos, productos, usuarios
// ================================
router.get('/activity', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();

    // Pedidos por día (últimos 14 días)
    // Intentar con columna 'total', fallback a 'precio_total' o 'monto_total'
    let ordersByDay = [];
    try {
      [ordersByDay] = await db.execute(`
        SELECT DATE(createdAt) AS dia, COUNT(*) AS total,
          COALESCE(SUM(total), SUM(precio_total), SUM(monto_total), 0) AS monto
        FROM orders
        WHERE createdAt >= DATE_SUB(NOW(), INTERVAL 14 DAY)
        GROUP BY DATE(createdAt)
        ORDER BY dia ASC
      `);
    } catch {
      try {
        [ordersByDay] = await db.execute(`
          SELECT DATE(createdAt) AS dia, COUNT(*) AS total, 0 AS monto
          FROM orders
          WHERE createdAt >= DATE_SUB(NOW(), INTERVAL 14 DAY)
          GROUP BY DATE(createdAt)
          ORDER BY dia ASC
        `);
      } catch { ordersByDay = []; }
    }

    // Productos creados por día (últimos 14 días)
    const [productsByDay] = await db.execute(`
      SELECT DATE(createdAt) AS dia, COUNT(*) AS total
      FROM products
      WHERE createdAt >= DATE_SUB(NOW(), INTERVAL 14 DAY)
      GROUP BY DATE(createdAt)
      ORDER BY dia ASC
    `);

    // Usuarios registrados por día (últimos 14 días)
    let usersByDay = [];
    for (const tbl of ['users','usuarios','clientes','user']) {
      try {
        [usersByDay] = await db.execute(`
          SELECT DATE(createdAt) AS dia, COUNT(*) AS total
          FROM ${tbl}
          WHERE createdAt >= DATE_SUB(NOW(), INTERVAL 14 DAY)
          GROUP BY DATE(createdAt)
          ORDER BY dia ASC
        `);
        break;
      } catch { continue; }
    }

    // Conteos totales
    let ordersRow = { total: 0, monto: 0 };
    try {
      const [[o]] = await db.execute(`SELECT COUNT(*) AS total, COALESCE(SUM(total), SUM(precio_total), SUM(monto_total), 0) AS monto FROM orders`);
      ordersRow = o;
    } catch {
      try { const [[o]] = await db.execute(`SELECT COUNT(*) AS total, 0 AS monto FROM orders`); ordersRow = o; } catch {}
    }
    const orders = ordersRow;
    const [[products]] = await db.execute(`SELECT COUNT(*) AS total FROM products WHERE activo = 1`);
    let usersRow = { total: 0 };
    for (const tbl of ['users','usuarios','clientes','user']) {
      try { const [[u]] = await db.execute(`SELECT COUNT(*) AS total FROM ${tbl}`); usersRow = u; break; } catch {}
    }
    const users = usersRow;
    const [[inventory]]= await db.execute(`SELECT COUNT(*) AS total, SUM(stock) AS units FROM inventory`);

    res.json({
      charts: {
        orders_by_day:   ordersByDay,
        products_by_day: productsByDay,
        users_by_day:    usersByDay,
      },
      totals: {
        orders:         ordersRow.total  || 0,
        orders_revenue: ordersRow.monto  || 0,
        products:       products.total   || 0,
        users:          users.total      || 0,
        inventory_rows: inventory.total  || 0,
        inventory_units:inventory.units  || 0,
      },
    });
  } catch (err) {
    console.error('Error en monitor activity:', err);
    res.status(500).json({ error: 'Error obteniendo actividad' });
  }
});

// ================================
// 🔍 GET /api/admin/monitor/integrity
// Chequeo de integridad: huérfanos, nulos, etc.
// ================================
router.get('/integrity', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const checks = [];

    // Inventario sin producto válido
    const [orphanInv] = await db.execute(`
      SELECT COUNT(*) AS total FROM inventory i
      LEFT JOIN products p ON p.id = i.product_id
      WHERE p.id IS NULL
    `);
    checks.push({ name: 'Inventario sin producto', value: orphanInv[0].total, status: orphanInv[0].total === 0 ? 'ok' : 'warn' });

    // Inventario sin sucursal válida
    const [orphanBranch] = await db.execute(`
      SELECT COUNT(*) AS total FROM inventory i
      LEFT JOIN branches b ON b.id = i.branch_id
      WHERE b.id IS NULL
    `);
    checks.push({ name: 'Inventario sin sucursal', value: orphanBranch[0].total, status: orphanBranch[0].total === 0 ? 'ok' : 'warn' });

    // Productos sin precio
    const [noPrice] = await db.execute(`SELECT COUNT(*) AS total FROM products WHERE precio IS NULL OR precio = 0`);
    checks.push({ name: 'Productos sin precio', value: noPrice[0].total, status: noPrice[0].total === 0 ? 'ok' : 'warn' });

    // Productos sin imagen
    const [noImg] = await db.execute(`SELECT COUNT(*) AS total FROM products WHERE imagen IS NULL OR imagen = ''`);
    checks.push({ name: 'Productos sin imagen', value: noImg[0].total, status: noImg[0].total === 0 ? 'ok' : 'info' });

    // Productos sin categoría
    const [noCat] = await db.execute(`SELECT COUNT(*) AS total FROM products WHERE categoria IS NULL OR categoria = ''`);
    checks.push({ name: 'Productos sin categoría', value: noCat[0].total, status: noCat[0].total === 0 ? 'ok' : 'info' });

    // Productos inactivos
    const [inactive] = await db.execute(`SELECT COUNT(*) AS total FROM products WHERE activo = 0`);
    checks.push({ name: 'Productos inactivos', value: inactive[0].total, status: 'info' });

    // Stock en cero
    const [zeroStock] = await db.execute(`SELECT COUNT(*) AS total FROM inventory WHERE stock = 0`);
    checks.push({ name: 'Registros con stock = 0', value: zeroStock[0].total, status: zeroStock[0].total === 0 ? 'ok' : 'warn' });

    // Sucursales sin inventario
    const [emptyBranches] = await db.execute(`
      SELECT COUNT(*) AS total FROM branches b
      LEFT JOIN inventory i ON i.branch_id = b.id
      WHERE i.id IS NULL AND b.activo = 1
    `).catch(() => [[{ total: 0 }]]);
    checks.push({ name: 'Sucursales sin inventario', value: emptyBranches[0].total, status: emptyBranches[0].total === 0 ? 'ok' : 'warn' });

    // Order items sin orden
    const [orphanItems] = await db.execute(`
      SELECT COUNT(*) AS total FROM order_items oi
      LEFT JOIN orders o ON o.id = oi.order_id
      WHERE o.id IS NULL
    `).catch(() => [[{ total: 0 }]]);
    checks.push({ name: 'Items de pedido huérfanos', value: orphanItems[0].total, status: orphanItems[0].total === 0 ? 'ok' : 'error' });

    res.json({ checks });
  } catch (err) {
    console.error('Error en monitor integrity:', err);
    res.status(500).json({ error: 'Error verificando integridad' });
  }
});

module.exports = router;

// ================================
// 🔍 GET /api/admin/monitor/schema
// Vistas, índices y usuarios de la BD
// ================================
router.get('/schema', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();

    // Vistas disponibles
    const [views] = await db.execute(`
      SELECT 
        table_name        AS view_name,
        view_definition   AS definition
      FROM information_schema.views
      WHERE table_schema = DATABASE()
      ORDER BY table_name
    `);

    // Índices (excluyendo PKs y los automáticos de information_schema)
    const [indexes] = await db.execute(`
      SELECT 
        s.table_name,
        s.index_name,
        s.column_name,
        s.non_unique,
        s.cardinality,
        s.index_type
      FROM information_schema.statistics s
      WHERE s.table_schema = DATABASE()
        AND s.index_name != 'PRIMARY'
      ORDER BY s.table_name, s.index_name, s.seq_in_index
    `);

    // Usuarios de la BD (solo los sl_*)
    let dbUsers = [];
    try {
      const [u] = await db.execute(
        `SELECT user AS username, host FROM mysql.user WHERE user LIKE 'sl_%'`
      );
      dbUsers = u;
    } catch { /* sin permiso a mysql.user — normal en Aiven */ }

    // Conteo de índices por tabla
    const [idxSummary] = await db.execute(`
      SELECT table_name, COUNT(DISTINCT index_name) AS total_indexes
      FROM information_schema.statistics
      WHERE table_schema = DATABASE() AND index_name != 'PRIMARY'
      GROUP BY table_name
      ORDER BY total_indexes DESC
    `);

    // Tamaño de cada vista (filas aproximadas)
    const viewStats = [];
    for (const v of views) {
      try {
        const [[stat]] = await db.execute(
          `SELECT COUNT(*) AS rows FROM \`${v.view_name}\``
        );
        viewStats.push({ name: v.view_name, rows: stat.rows });
      } catch {
        viewStats.push({ name: v.view_name, rows: null });
      }
    }

    res.json({
      views:      viewStats,
      indexes,
      idx_summary: idxSummary,
      db_users:   dbUsers,
    });
  } catch (err) {
    console.error('Error en monitor schema:', err);
    res.status(500).json({ error: 'Error obteniendo schema' });
  }
});