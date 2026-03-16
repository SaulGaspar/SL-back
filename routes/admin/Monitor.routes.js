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
      SELECT table_name, table_rows,
        ROUND((data_length + index_length) / 1024, 2) AS size_kb,
        ROUND(data_length / 1024, 2) AS data_kb,
        ROUND(index_length / 1024, 2) AS index_kb,
        create_time, update_time, engine
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
        name:      t.table_name,
        rows:      t.table_rows      || 0,
        size_kb:   t.size_kb         || 0,
        data_kb:   t.data_kb         || 0,
        index_kb:  t.index_kb        || 0,
        engine:    t.engine          || 'N/A',
        created:   t.create_time,
        updated:   t.update_time,
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
    const [ordersByDay] = await db.execute(`
      SELECT DATE(createdAt) AS dia, COUNT(*) AS total,
        SUM(total) AS monto
      FROM orders
      WHERE createdAt >= DATE_SUB(NOW(), INTERVAL 14 DAY)
      GROUP BY DATE(createdAt)
      ORDER BY dia ASC
    `);

    // Productos creados por día (últimos 14 días)
    const [productsByDay] = await db.execute(`
      SELECT DATE(createdAt) AS dia, COUNT(*) AS total
      FROM products
      WHERE createdAt >= DATE_SUB(NOW(), INTERVAL 14 DAY)
      GROUP BY DATE(createdAt)
      ORDER BY dia ASC
    `);

    // Usuarios registrados por día (últimos 14 días)
    const [usersByDay] = await db.execute(`
      SELECT DATE(createdAt) AS dia, COUNT(*) AS total
      FROM users
      WHERE createdAt >= DATE_SUB(NOW(), INTERVAL 14 DAY)
      GROUP BY DATE(createdAt)
      ORDER BY dia ASC
    `).catch(() => [[]]); // users puede llamarse diferente

    // Conteos totales
    const [[orders]]   = await db.execute(`SELECT COUNT(*) AS total, SUM(total) AS monto FROM orders`);
    const [[products]] = await db.execute(`SELECT COUNT(*) AS total FROM products WHERE activo = 1`);
    const [[users]]    = await db.execute(`SELECT COUNT(*) AS total FROM users`).catch(() => [[{ total: 0 }]]);
    const [[inventory]]= await db.execute(`SELECT COUNT(*) AS total, SUM(stock) AS units FROM inventory`);

    res.json({
      charts: {
        orders_by_day:   ordersByDay,
        products_by_day: productsByDay,
        users_by_day:    usersByDay,
      },
      totals: {
        orders:         orders.total     || 0,
        orders_revenue: orders.monto     || 0,
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