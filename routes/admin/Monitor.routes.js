const express = require('express');
const router = express.Router();
const { getDB } = require('../../config/db');
const { authMiddleware, adminOnly } = require('../../middlewares/auth');

// ================================
// 📊 GET /api/admin/monitor/overview
// ================================
router.get('/overview', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();

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

    const [tables] = await db.execute(`
      SELECT COUNT(*) AS total FROM information_schema.tables
      WHERE table_schema = DATABASE()
    `);

    const [uptime]      = await db.execute(`SHOW STATUS LIKE 'Uptime'`);
    const [connections] = await db.execute(`SHOW STATUS LIKE 'Threads_connected'`);
    const [maxConn]     = await db.execute(`SHOW VARIABLES LIKE 'max_connections'`);
    const [queries]     = await db.execute(`SHOW STATUS LIKE 'Queries'`);
    const [slowQ]       = await db.execute(`SHOW STATUS LIKE 'Slow_queries'`);
    const [version]     = await db.execute(`SELECT VERSION() AS version`);
    const [charset]     = await db.execute(`SHOW VARIABLES LIKE 'character_set_database'`);

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
        name:     dbSize[0]?.db_name  || dbSize[0]?.DB_NAME  || 'N/A',
        size_mb:  dbSize[0]?.size_mb  || dbSize[0]?.SIZE_MB  || 0,
        data_mb:  dbSize[0]?.data_mb  || dbSize[0]?.DATA_MB  || 0,
        index_mb: dbSize[0]?.index_mb || dbSize[0]?.INDEX_MB || 0,
        tables:   tables[0]?.total    || tables[0]?.TOTAL    || 0,
        version:  version[0]?.version || version[0]?.VERSION || 'N/A',
        charset:  charset[0]?.Value   || charset[0]?.value   || 'N/A',
      },
      server: {
        uptime_seconds:  parseInt(uptime[0]?.Value      || uptime[0]?.value      || 0),
        connections:     parseInt(connections[0]?.Value || connections[0]?.value || 0),
        max_connections: parseInt(maxConn[0]?.Value     || maxConn[0]?.value     || 0),
        total_queries:   parseInt(queries[0]?.Value     || queries[0]?.value     || 0),
        slow_queries:    parseInt(slowQ[0]?.Value       || slowQ[0]?.value       || 0),
      },
      tables: rowCounts.map(t => ({
        name:    t.tname    || t.TNAME    || t.table_name || t.TABLE_NAME || '?',
        rows:    t.trows    || t.TROWS    || t.table_rows || t.TABLE_ROWS || 0,
        size_kb: t.size_kb  || t.SIZE_KB  || 0,
        data_kb: t.data_kb  || t.DATA_KB  || 0,
        index_kb:t.index_kb || t.INDEX_KB || 0,
        engine:  t.tengine  || t.TENGINE  || t.engine     || t.ENGINE    || 'N/A',
        created: t.created_at || t.CREATED_AT || t.create_time,
        updated: t.updated_at || t.UPDATED_AT || t.update_time,
      })),
    });
  } catch (err) {
    console.error('Error en monitor overview:', err);
    res.status(500).json({ error: 'Error obteniendo métricas de BD' });
  }
});

// ================================
// 📈 GET /api/admin/monitor/activity
// ================================
router.get('/activity', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();

    let ordersByDay = [];
    try {
      [ordersByDay] = await db.execute(`
        SELECT DATE(createdAt) AS dia, COUNT(*) AS total,
          COALESCE(SUM(total), SUM(precio_total), SUM(monto_total), 0) AS monto
        FROM orders WHERE createdAt >= DATE_SUB(NOW(), INTERVAL 14 DAY)
        GROUP BY DATE(createdAt) ORDER BY dia ASC
      `);
    } catch {
      try {
        [ordersByDay] = await db.execute(`
          SELECT DATE(createdAt) AS dia, COUNT(*) AS total, 0 AS monto
          FROM orders WHERE createdAt >= DATE_SUB(NOW(), INTERVAL 14 DAY)
          GROUP BY DATE(createdAt) ORDER BY dia ASC
        `);
      } catch { ordersByDay = []; }
    }

    const [productsByDay] = await db.execute(`
      SELECT DATE(createdAt) AS dia, COUNT(*) AS total
      FROM products WHERE createdAt >= DATE_SUB(NOW(), INTERVAL 14 DAY)
      GROUP BY DATE(createdAt) ORDER BY dia ASC
    `);

    let usersByDay = [];
    for (const tbl of ['users','usuarios','clientes','user']) {
      try {
        [usersByDay] = await db.execute(`
          SELECT DATE(createdAt) AS dia, COUNT(*) AS total
          FROM ${tbl} WHERE createdAt >= DATE_SUB(NOW(), INTERVAL 14 DAY)
          GROUP BY DATE(createdAt) ORDER BY dia ASC
        `);
        break;
      } catch { continue; }
    }

    let ordersRow = { total: 0, monto: 0 };
    try {
      const [[o]] = await db.execute(`SELECT COUNT(*) AS total, COALESCE(SUM(total), SUM(precio_total), SUM(monto_total), 0) AS monto FROM orders`);
      ordersRow = o;
    } catch {
      try { const [[o]] = await db.execute(`SELECT COUNT(*) AS total, 0 AS monto FROM orders`); ordersRow = o; } catch {}
    }

    const [[products]]  = await db.execute(`SELECT COUNT(*) AS total FROM products WHERE activo = 1`);
    const [[inventory]] = await db.execute(`SELECT COUNT(*) AS total, SUM(stock) AS units FROM inventory`);

    let usersRow = { total: 0 };
    for (const tbl of ['users','usuarios','clientes','user']) {
      try { const [[u]] = await db.execute(`SELECT COUNT(*) AS total FROM ${tbl}`); usersRow = u; break; } catch {}
    }

    res.json({
      charts: {
        orders_by_day:   ordersByDay,
        products_by_day: productsByDay,
        users_by_day:    usersByDay,
      },
      totals: {
        orders:          ordersRow.total  || 0,
        orders_revenue:  ordersRow.monto  || 0,
        products:        products.total   || 0,
        users:           usersRow.total   || 0,
        inventory_rows:  inventory.total  || 0,
        inventory_units: inventory.units  || 0,
      },
    });
  } catch (err) {
    console.error('Error en monitor activity:', err);
    res.status(500).json({ error: 'Error obteniendo actividad' });
  }
});

// ================================
// 🔍 GET /api/admin/monitor/integrity
// ================================
router.get('/integrity', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const checks = [];

    const [orphanInv] = await db.execute(`SELECT COUNT(*) AS total FROM inventory i LEFT JOIN products p ON p.id = i.product_id WHERE p.id IS NULL`);
    checks.push({ name: 'Inventario sin producto', value: orphanInv[0].total, status: orphanInv[0].total === 0 ? 'ok' : 'warn' });

    const [orphanBranch] = await db.execute(`SELECT COUNT(*) AS total FROM inventory i LEFT JOIN branches b ON b.id = i.branch_id WHERE b.id IS NULL`);
    checks.push({ name: 'Inventario sin sucursal', value: orphanBranch[0].total, status: orphanBranch[0].total === 0 ? 'ok' : 'warn' });

    const [noPrice] = await db.execute(`SELECT COUNT(*) AS total FROM products WHERE precio IS NULL OR precio = 0`);
    checks.push({ name: 'Productos sin precio', value: noPrice[0].total, status: noPrice[0].total === 0 ? 'ok' : 'warn' });

    const [noImg] = await db.execute(`SELECT COUNT(*) AS total FROM products WHERE imagen IS NULL OR imagen = ''`);
    checks.push({ name: 'Productos sin imagen', value: noImg[0].total, status: noImg[0].total === 0 ? 'ok' : 'info' });

    const [noCat] = await db.execute(`SELECT COUNT(*) AS total FROM products WHERE categoria IS NULL OR categoria = ''`);
    checks.push({ name: 'Productos sin categoría', value: noCat[0].total, status: noCat[0].total === 0 ? 'ok' : 'info' });

    const [inactive] = await db.execute(`SELECT COUNT(*) AS total FROM products WHERE activo = 0`);
    checks.push({ name: 'Productos inactivos', value: inactive[0].total, status: 'info' });

    const [zeroStock] = await db.execute(`SELECT COUNT(*) AS total FROM inventory WHERE stock = 0`);
    checks.push({ name: 'Registros con stock = 0', value: zeroStock[0].total, status: zeroStock[0].total === 0 ? 'ok' : 'warn' });

    const [emptyBranches] = await db.execute(`
      SELECT COUNT(*) AS total FROM branches b
      LEFT JOIN inventory i ON i.branch_id = b.id
      WHERE i.id IS NULL AND b.activo = 1
    `).catch(() => [[{ total: 0 }]]);
    checks.push({ name: 'Sucursales sin inventario', value: emptyBranches[0].total, status: emptyBranches[0].total === 0 ? 'ok' : 'warn' });

    const [orphanItems] = await db.execute(`
      SELECT COUNT(*) AS total FROM order_items oi
      LEFT JOIN orders o ON o.id = oi.order_id WHERE o.id IS NULL
    `).catch(() => [[{ total: 0 }]]);
    checks.push({ name: 'Items de pedido huérfanos', value: orphanItems[0].total, status: orphanItems[0].total === 0 ? 'ok' : 'error' });

    res.json({ checks });
  } catch (err) {
    console.error('Error en monitor integrity:', err);
    res.status(500).json({ error: 'Error verificando integridad' });
  }
});

// ================================
// 🗄️ GET /api/admin/monitor/schema
// ================================
router.get('/schema', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();

    const [views] = await db.execute(`
      SELECT table_name AS view_name
      FROM information_schema.views
      WHERE table_schema = DATABASE()
      ORDER BY table_name
    `);

    const viewStats = [];
    for (const v of views) {
      const vname = v.view_name || v.VIEW_NAME || v.TABLE_NAME || v.table_name;
      if (!vname) continue;
      try {
        const [[stat]] = await db.execute(`SELECT COUNT(*) AS rows FROM \`${vname}\``);
        viewStats.push({ name: vname, rows: stat.rows ?? stat.ROWS ?? null });
      } catch {
        viewStats.push({ name: vname, rows: null });
      }
    }

    const [tableList] = await db.execute(`
      SELECT table_name AS tname
      FROM information_schema.tables
      WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'
    `);

    const indexes    = [];
    const idxSummary = [];

    for (const t of tableList) {
      const tname = t.tname || t.TNAME || t.table_name || t.TABLE_NAME;
      if (!tname) continue;
      try {
        const [idxRows] = await db.execute(`SHOW INDEX FROM \`${tname}\``);
        const custom = idxRows.filter(r => {
          const kname = r.Key_name || r.KEY_NAME || r.key_name || '';
          return kname !== 'PRIMARY';
        });
        if (custom.length > 0) {
          const uniqueKeys = new Set(custom.map(r => r.Key_name || r.KEY_NAME || r.key_name));
          idxSummary.push({ table_name: tname, total_indexes: uniqueKeys.size });
          for (const r of custom) {
            indexes.push({
              table_name:  tname,
              index_name:  r.Key_name    || r.KEY_NAME    || r.key_name    || '',
              column_name: r.Column_name || r.COLUMN_NAME || r.column_name || '',
              non_unique:  r.Non_unique  ?? r.NON_UNIQUE  ?? r.non_unique  ?? 1,
              cardinality: r.Cardinality || r.CARDINALITY || r.cardinality || null,
              index_type:  r.Index_type  || r.INDEX_TYPE  || r.index_type  || 'BTREE',
            });
          }
        }
      } catch { }
    }

    idxSummary.sort((a, b) => b.total_indexes - a.total_indexes);

    let dbUsers = [];
    try {
      const [u] = await db.execute(`SELECT user AS username, host FROM mysql.user WHERE user LIKE 'sl_%'`);
      dbUsers = u;
    } catch { }

    res.json({
      views:       viewStats,
      indexes,
      idx_summary: idxSummary,
      db_users:    dbUsers,
    });
  } catch (err) {
    console.error('Error en monitor schema:', err);
    res.status(500).json({ error: 'Error obteniendo schema' });
  }
});

// ================================
// ⚡ GET /api/admin/monitor/performance
// ================================
router.get('/performance', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();

    const statusVars = [
      'Innodb_buffer_pool_reads',
      'Innodb_buffer_pool_read_requests',
      'Innodb_buffer_pool_pages_data',
      'Innodb_buffer_pool_pages_total',
      'Innodb_rows_read',
      'Innodb_rows_inserted',
      'Innodb_rows_updated',
      'Innodb_rows_deleted',
      'Table_locks_waited',
      'Table_locks_immediate',
      'Innodb_row_lock_waits',
      'Innodb_row_lock_time_avg',
      'Sort_rows',
      'Sort_merge_passes',
      'Handler_read_rnd_next',
      'Handler_read_key',
      'Created_tmp_disk_tables',
      'Created_tmp_tables',
      'Select_full_join',
      'Select_scan',
    ];

    const statusMap = {};
    for (const varName of statusVars) {
      try {
        const [rows] = await db.execute(`SHOW STATUS LIKE ?`, [varName]);
        if (rows.length > 0) statusMap[varName] = parseInt(rows[0].Value || rows[0].value || 0);
      } catch { statusMap[varName] = null; }
    }

    const reads    = statusMap['Innodb_buffer_pool_reads']         || 0;
    const requests = statusMap['Innodb_buffer_pool_read_requests'] || 1;
    const bufferHitRate = requests > 0
      ? parseFloat(((1 - reads / requests) * 100).toFixed(2))
      : null;

    const tmpDisk  = statusMap['Created_tmp_disk_tables'] || 0;
    const tmpTotal = statusMap['Created_tmp_tables']      || 1;
    const tmpDiskRatio = tmpTotal > 0 ? parseFloat(((tmpDisk / tmpTotal) * 100).toFixed(2)) : 0;

    const rndNext = statusMap['Handler_read_rnd_next'] || 0;
    const readKey = statusMap['Handler_read_key']       || 1;
    const fullScanRatio = (rndNext + readKey) > 0
      ? parseFloat(((rndNext / (rndNext + readKey)) * 100).toFixed(2))
      : 0;

    let slowQueries = [];
    try {
      const [rows] = await db.execute(`
        SELECT
          DIGEST_TEXT                                       AS query_digest,
          COUNT_STAR                                        AS exec_count,
          ROUND(AVG_TIMER_WAIT / 1000000000000, 4)         AS avg_sec,
          ROUND(MAX_TIMER_WAIT / 1000000000000, 4)         AS max_sec,
          ROUND(SUM_TIMER_WAIT / 1000000000000, 4)         AS total_sec,
          SUM_ROWS_EXAMINED                                 AS rows_examined,
          SUM_ROWS_SENT                                     AS rows_sent,
          SUM_NO_INDEX_USED                                 AS no_index_count,
          FIRST_SEEN                                        AS first_seen,
          LAST_SEEN                                         AS last_seen
        FROM performance_schema.events_statements_summary_by_digest
        WHERE DIGEST_TEXT IS NOT NULL
          AND SCHEMA_NAME = DATABASE()
        ORDER BY AVG_TIMER_WAIT DESC
        LIMIT 15
      `);
      slowQueries = rows.map(r => ({
        digest:          (r.query_digest || r.QUERY_DIGEST || '').substring(0, 120),
        exec_count:      r.exec_count     || r.EXEC_COUNT     || 0,
        avg_sec:         r.avg_sec        || r.AVG_SEC        || 0,
        max_sec:         r.max_sec        || r.MAX_SEC        || 0,
        total_sec:       r.total_sec      || r.TOTAL_SEC      || 0,
        rows_examined:   r.rows_examined  || r.ROWS_EXAMINED  || 0,
        rows_sent:       r.rows_sent      || r.ROWS_SENT      || 0,
        no_index_count:  r.no_index_count || r.NO_INDEX_COUNT || 0,
        first_seen:      r.first_seen     || r.FIRST_SEEN,
        last_seen:       r.last_seen      || r.LAST_SEEN,
      }));
    } catch { slowQueries = []; }

    let tableIO = [];
    try {
      const [rows] = await db.execute(`
        SELECT
          OBJECT_NAME                                                AS table_name,
          COUNT_READ                                                 AS reads,
          COUNT_WRITE                                                AS writes,
          COUNT_READ + COUNT_WRITE                                   AS total_ops,
          ROUND(SUM_TIMER_READ / 1000000000000, 4)                  AS read_sec,
          ROUND(SUM_TIMER_WRITE / 1000000000000, 4)                 AS write_sec
        FROM performance_schema.table_io_waits_summary_by_table
        WHERE OBJECT_SCHEMA = DATABASE()
          AND (COUNT_READ + COUNT_WRITE) > 0
        ORDER BY (COUNT_READ + COUNT_WRITE) DESC
        LIMIT 12
      `);
      tableIO = rows.map(r => ({
        table_name: r.table_name || r.TABLE_NAME || '?',
        reads:      parseInt(r.reads      || r.READS      || 0),
        writes:     parseInt(r.writes     || r.WRITES     || 0),
        total_ops:  parseInt(r.total_ops  || r.TOTAL_OPS  || 0),
        read_sec:   parseFloat(r.read_sec  || r.READ_SEC  || 0),
        write_sec:  parseFloat(r.write_sec || r.WRITE_SEC || 0),
      }));
    } catch { tableIO = []; }

    const lockInfo = {
      waits:          statusMap['Innodb_row_lock_waits']    || 0,
      avg_wait_ms:    statusMap['Innodb_row_lock_time_avg'] || 0,
      lock_immediate: statusMap['Table_locks_immediate']    || 0,
      lock_waited:    statusMap['Table_locks_waited']       || 0,
    };

    res.json({
      buffer: {
        hit_rate_pct:    bufferHitRate,
        reads_from_disk: reads,
        total_requests:  requests,
        pages_data:      statusMap['Innodb_buffer_pool_pages_data']  || 0,
        pages_total:     statusMap['Innodb_buffer_pool_pages_total'] || 0,
      },
      operations: {
        rows_read:     statusMap['Innodb_rows_read']     || 0,
        rows_inserted: statusMap['Innodb_rows_inserted'] || 0,
        rows_updated:  statusMap['Innodb_rows_updated']  || 0,
        rows_deleted:  statusMap['Innodb_rows_deleted']  || 0,
      },
      efficiency: {
        tmp_disk_ratio_pct:  tmpDiskRatio,
        full_scan_ratio_pct: fullScanRatio,
        sort_merge_passes:   statusMap['Sort_merge_passes'] || 0,
        select_full_join:    statusMap['Select_full_join']  || 0,
        select_scan:         statusMap['Select_scan']       || 0,
      },
      locks:       lockInfo,
      slow_queries: slowQueries,
      table_io:     tableIO,
    });
  } catch (err) {
    console.error('Error en monitor performance:', err);
    res.status(500).json({ error: 'Error obteniendo métricas de rendimiento' });
  }
});

// ================================
// 🔄 GET /api/admin/monitor/processes
// ================================
router.get('/processes', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();

    let processes = [];
    try {
      const [rows] = await db.execute(`
        SELECT ID AS id, USER AS db_user, HOST AS host, DB AS db_name,
               COMMAND AS command, TIME AS time_sec, STATE AS state,
               LEFT(INFO, 200) AS query_preview
        FROM information_schema.PROCESSLIST
        WHERE COMMAND != 'Sleep' OR TIME > 5
        ORDER BY TIME DESC LIMIT 30
      `);
      processes = rows.map(r => ({
        id:            r.id            || r.ID,
        db_user:       r.db_user       || r.DB_USER  || '?',
        host:          r.host          || r.HOST      || '?',
        db_name:       r.db_name       || r.DB_NAME   || '?',
        command:       r.command       || r.COMMAND   || '?',
        time_sec:      parseInt(r.time_sec || r.TIME_SEC || 0),
        state:         r.state         || r.STATE     || '',
        query_preview: r.query_preview || r.QUERY_PREVIEW || null,
      }));
    } catch { processes = []; }

    let transactions = [];
    try {
      const [rows] = await db.execute(`
        SELECT trx_id, trx_state AS state, trx_started AS started,
               TIMESTAMPDIFF(SECOND, trx_started, NOW()) AS duration_sec,
               trx_rows_locked AS rows_locked, trx_rows_modified AS rows_modified,
               trx_tables_in_use AS tables_in_use, trx_tables_locked AS tables_locked,
               trx_query AS current_query
        FROM information_schema.INNODB_TRX ORDER BY trx_started ASC LIMIT 20
      `);
      transactions = rows.map(r => ({
        trx_id:        r.trx_id        || r.TRX_ID        || '?',
        state:         r.state         || r.STATE         || '?',
        started:       r.started       || r.STARTED,
        duration_sec:  parseInt(r.duration_sec || 0),
        rows_locked:   parseInt(r.rows_locked  || 0),
        rows_modified: parseInt(r.rows_modified|| 0),
        tables_in_use: parseInt(r.tables_in_use|| 0),
        tables_locked: parseInt(r.tables_locked|| 0),
        current_query: r.current_query  || null,
      }));
    } catch { transactions = []; }

    let locks = [];
    try {
      const [rows] = await db.execute(`
        SELECT ENGINE_LOCK_ID AS lock_id, ENGINE_TRANSACTION_ID AS trx_id,
               OBJECT_SCHEMA AS db_name, OBJECT_NAME AS table_name,
               LOCK_TYPE AS lock_type, LOCK_MODE AS lock_mode,
               LOCK_STATUS AS lock_status, LOCK_DATA AS lock_data
        FROM performance_schema.data_locks
        WHERE OBJECT_SCHEMA = DATABASE() LIMIT 30
      `);
      locks = rows.map(r => ({
        lock_id:     r.lock_id     || '?',
        trx_id:      r.trx_id,
        table_name:  r.table_name  || '?',
        lock_type:   r.lock_type   || '?',
        lock_mode:   r.lock_mode   || '?',
        lock_status: r.lock_status || '?',
        lock_data:   r.lock_data   || null,
      }));
    } catch {
      try {
        const [rows] = await db.execute(`
          SELECT lock_id, lock_trx_id AS trx_id, lock_table AS table_name,
                 lock_type, lock_mode, 'GRANTED' AS lock_status, lock_data
          FROM information_schema.INNODB_LOCKS LIMIT 30
        `);
        locks = rows;
      } catch { locks = []; }
    }

    const stateSummary = {};
    for (const p of processes) {
      const s = p.state || p.command || 'unknown';
      stateSummary[s] = (stateSummary[s] || 0) + 1;
    }

    res.json({
      processes,
      transactions,
      locks,
      summary: {
        total_processes:    processes.length,
        total_transactions: transactions.length,
        total_locks:        locks.length,
        long_running:       processes.filter(p => p.time_sec > 10).length,
        state_summary:      stateSummary,
      },
    });
  } catch (err) {
    console.error('Error en monitor processes:', err);
    res.status(500).json({ error: 'Error obteniendo procesos activos' });
  }
});

// ================================
// 🔧 GET /api/admin/monitor/maintenance
// Salud de tablas: fragmentación (data_free), índices y selectividad
// ================================
router.get('/maintenance', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();

    const [tableHealth] = await db.execute(`
      SELECT
        table_name                                              AS tname,
        engine                                                  AS engine,
        table_rows                                              AS est_rows,
        ROUND(data_length   / 1024, 2)                          AS data_kb,
        ROUND(index_length  / 1024, 2)                          AS index_kb,
        ROUND(data_free     / 1024, 2)                          AS free_kb,
        ROUND((data_length + index_length) / 1024, 2)           AS total_kb,
        ROUND(
          IF(data_length > 0, (data_free / data_length) * 100, 0), 2
        )                                                        AS frag_pct,
        create_time                                              AS created_at,
        update_time                                              AS updated_at,
        table_collation                                          AS collation
      FROM information_schema.tables
      WHERE table_schema = DATABASE()
        AND table_type   = 'BASE TABLE'
      ORDER BY frag_pct DESC, (data_length + index_length) DESC
    `);

    const [tableList] = await db.execute(`
      SELECT table_name AS tname
      FROM information_schema.tables
      WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'
    `);

    const indexHealth = [];
    for (const t of tableList) {
      const tname = t.tname || t.TNAME || t.table_name || t.TABLE_NAME;
      if (!tname) continue;
      try {
        const [idxRows] = await db.execute(`SHOW INDEX FROM \`${tname}\``);
        for (const r of idxRows) {
          const keyName     = r.Key_name    || r.KEY_NAME    || r.key_name    || '';
          const colName     = r.Column_name || r.COLUMN_NAME || r.column_name || '';
          const cardinality = parseInt(r.Cardinality || r.CARDINALITY || r.cardinality || 0);
          const nonUnique   = r.Non_unique  ?? r.NON_UNIQUE  ?? r.non_unique  ?? 1;
          const idxType     = r.Index_type  || r.INDEX_TYPE  || r.index_type  || 'BTREE';

          const tableRow  = tableHealth.find(th =>
            (th.tname || th.TNAME || '').toLowerCase() === tname.toLowerCase()
          );
          const estRows   = parseInt(tableRow?.est_rows || tableRow?.EST_ROWS || 1);
          const selectivity = estRows > 0 ? Math.min((cardinality / estRows) * 100, 100) : null;

          indexHealth.push({
            table_name:      tname,
            key_name:        keyName,
            column_name:     colName,
            is_primary:      keyName === 'PRIMARY',
            is_unique:       nonUnique === 0 || nonUnique === '0',
            index_type:      idxType,
            cardinality,
            est_rows:        estRows,
            selectivity_pct: selectivity !== null ? parseFloat(selectivity.toFixed(2)) : null,
          });
        }
      } catch { }
    }

    const highFrag       = tableHealth.filter(t => parseFloat(t.frag_pct || t.FRAG_PCT || 0) > 20);
    const lowSelectivity = indexHealth.filter(
      i => !i.is_primary && i.selectivity_pct !== null && i.selectivity_pct < 10 && i.cardinality > 0
    );

    const totalFreeKB   = tableHealth.reduce((a, t) => a + parseFloat(t.free_kb  || t.FREE_KB  || 0), 0);
    const totalDataKB   = tableHealth.reduce((a, t) => a + parseFloat(t.data_kb  || t.DATA_KB  || 0), 0);
    const globalFragPct = totalDataKB > 0 ? parseFloat(((totalFreeKB / totalDataKB) * 100).toFixed(2)) : 0;

    res.json({
      summary: {
        total_tables:        tableHealth.length,
        high_frag_tables:    highFrag.length,
        low_selectivity_idx: lowSelectivity.length,
        total_free_kb:       parseFloat(totalFreeKB.toFixed(2)),
        global_frag_pct:     globalFragPct,
      },
      table_health: tableHealth.map(t => ({
        name:       t.tname      || t.TNAME      || '?',
        engine:     t.engine     || t.ENGINE     || 'InnoDB',
        est_rows:   parseInt(t.est_rows   || t.EST_ROWS   || 0),
        data_kb:    parseFloat(t.data_kb  || t.DATA_KB    || 0),
        index_kb:   parseFloat(t.index_kb || t.INDEX_KB   || 0),
        free_kb:    parseFloat(t.free_kb  || t.FREE_KB    || 0),
        total_kb:   parseFloat(t.total_kb || t.TOTAL_KB   || 0),
        frag_pct:   parseFloat(t.frag_pct || t.FRAG_PCT   || 0),
        updated_at: t.updated_at || t.UPDATED_AT,
        collation:  t.collation  || t.COLLATION  || '—',
        status:     parseFloat(t.frag_pct || t.FRAG_PCT || 0) > 30 ? 'critical'
                  : parseFloat(t.frag_pct || t.FRAG_PCT || 0) > 10 ? 'warn'
                  : 'ok',
      })),
      index_health:    indexHealth,
      high_frag:       highFrag,
      low_selectivity: lowSelectivity,
    });
  } catch (err) {
    console.error('Error en monitor maintenance:', err);
    res.status(500).json({ error: 'Error obteniendo datos de mantenimiento' });
  }
});

// ================================
// ⚙️ POST /api/admin/monitor/optimize
// Ejecuta ANALYZE TABLE + OPTIMIZE TABLE
// Body: { tables: ['t1','t2'] }  (opcional)
// ================================
router.post('/optimize', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const { tables: targetTables } = req.body || {};

    let tablesToOptimize = [];
    if (targetTables && targetTables.length > 0) {
      tablesToOptimize = targetTables;
    } else {
      const [rows] = await db.execute(`
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = DATABASE()
          AND table_type   = 'BASE TABLE'
          AND data_free    > 0
        ORDER BY (data_free / GREATEST(data_length, 1)) DESC
        LIMIT 20
      `);
      tablesToOptimize = rows.map(r => r.table_name || r.TABLE_NAME);
    }

    const results   = [];
    const startTime = Date.now();

    for (const tname of tablesToOptimize) {
      const t0 = Date.now();
      try {
        await db.execute(`ANALYZE TABLE \`${tname}\``);
        await db.execute(`OPTIMIZE TABLE \`${tname}\``);
        results.push({ table: tname, status: 'ok', ms: Date.now() - t0 });
      } catch (e) {
        results.push({ table: tname, status: 'error', error: e.message, ms: Date.now() - t0 });
      }
    }

    const totalMs = Date.now() - startTime;
    const ok      = results.filter(r => r.status === 'ok').length;

    console.log(`🔧 OPTIMIZE por ${req.user?.usuario}: ${ok}/${results.length} tablas en ${totalMs}ms`);

    res.json({ ok, total: results.length, total_ms: totalMs, results });
  } catch (err) {
    console.error('Error en optimize:', err);
    res.status(500).json({ error: 'Error ejecutando optimización' });
  }
});

module.exports = router;