const express = require('express');
const router  = express.Router();
const { getDB }                     = require('../../config/db');
const { authMiddleware, adminOnly } = require('../../middlewares/auth');

// ══════════════════════════════════════════════════
// 📊 GET /api/admin/reports/summary
// KPIs generales del período
// ══════════════════════════════════════════════════
router.get('/summary', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const { from, to, branch } = req.query;

    const whereArr = [];
    const p = [];
    if (from)                        { whereArr.push('DATE(o.fecha) >= ?'); p.push(from); }
    if (to)                          { whereArr.push('DATE(o.fecha) <= ?'); p.push(to); }
    if (branch && branch !== 'all')  { whereArr.push('o.sucursal = ?');     p.push(branch); }
    const where = whereArr.length ? 'WHERE ' + whereArr.join(' AND ') : 'WHERE 1=1';

    const [[cur]] = await db.execute(`
      SELECT
        COUNT(o.id)                                                        AS total_pedidos,
        COALESCE(SUM(CASE WHEN o.status != 'cancelado' THEN o.total END), 0) AS ingresos,
        COALESCE(AVG(CASE WHEN o.status != 'cancelado' THEN o.total END), 0) AS ticket_promedio,
        COUNT(DISTINCT o.user_id)                                          AS clientes_unicos,
        SUM(CASE WHEN o.status = 'cancelado' THEN 1 ELSE 0 END)           AS cancelados,
        SUM(CASE WHEN o.status = 'entregado' THEN 1 ELSE 0 END)           AS entregados,
        SUM(CASE WHEN o.status = 'pendiente' THEN 1 ELSE 0 END)           AS pendientes
      FROM orders o ${where}
    `, p);

    let prev = { ingresos: 0, total_pedidos: 0, clientes_unicos: 0 };
    if (from && to) {
      const days = Math.ceil((new Date(to) - new Date(from)) / 86400000);
      const prevFrom = new Date(new Date(from) - days * 86400000).toISOString().slice(0,10);
      const prevTo   = new Date(new Date(from) - 86400000).toISOString().slice(0,10);
      const [[pp]] = await db.execute(`
        SELECT
          COUNT(o.id) AS total_pedidos,
          COALESCE(SUM(CASE WHEN o.status != 'cancelado' THEN o.total END), 0) AS ingresos,
          COUNT(DISTINCT o.user_id) AS clientes_unicos
        FROM orders o
        WHERE DATE(o.fecha) >= ? AND DATE(o.fecha) <= ?
      `, [prevFrom, prevTo]);
      prev = pp;
    }

    res.json({ current: cur, previous: prev });
  } catch (err) {
    console.error('Error summary:', err);
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════════
// 📈 GET /api/admin/reports/timeline
// ══════════════════════════════════════════════════
router.get('/timeline', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const { from, to, branch } = req.query;

    const whereArr = [];
    const p = [];
    if (from)                        { whereArr.push('o.fecha >= ?');   p.push(from); }
    if (to)                          { whereArr.push('o.fecha <= ?');   p.push(to); }
    if (branch && branch !== 'all')  { whereArr.push('o.sucursal = ?'); p.push(branch); }
    const where = whereArr.length ? 'WHERE ' + whereArr.join(' AND ') : '';

    const [rows] = await db.execute(`
      SELECT
        DATE(o.fecha)    AS dia,
        COUNT(o.id)      AS pedidos,
        SUM(o.total)     AS ingresos,
        AVG(o.total)     AS ticket
      FROM orders o ${where}
      GROUP BY DATE(o.fecha)
      ORDER BY dia ASC
    `, p);

    res.json(rows);
  } catch (err) {
    console.error('Error timeline:', err);
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════════
// 🏪 GET /api/admin/reports/by-branch
// ══════════════════════════════════════════════════
router.get('/by-branch', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const { from, to } = req.query;

    let where = "WHERE o.status != 'cancelado'";
    const p = [];
    if (from) { where += ' AND DATE(o.fecha) >= ?'; p.push(from); }
    if (to)   { where += ' AND DATE(o.fecha) <= ?'; p.push(to); }

    const [rows] = await db.execute(`
      SELECT
        COALESCE(b.nombre, 'Sin asignar')      AS sucursal,
        COUNT(o.id)                             AS pedidos,
        COALESCE(SUM(o.total), 0)              AS ingresos,
        COALESCE(AVG(o.total), 0)              AS ticket_promedio,
        COUNT(DISTINCT o.user_id)               AS clientes_unicos,
        SUM(CASE WHEN o.status='cancelado' THEN 1 ELSE 0 END) AS cancelados
      FROM orders o
      LEFT JOIN branches b ON b.id = o.sucursal
      ${where}
      GROUP BY o.sucursal, b.nombre
      ORDER BY ingresos DESC
    `, p);

    res.json(rows);
  } catch (err) {
    console.error('Error by-branch:', err);
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════════
// 🛍️ GET /api/admin/reports/top-products
// ══════════════════════════════════════════════════
router.get('/top-products', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const { from, to, branch, limit = 10 } = req.query;

    const where  = [];
    const params = [];
    if (from)                        { where.push('o.fecha >= ?');    params.push(from); }
    if (to)                          { where.push('o.fecha <= ?');    params.push(to); }
    if (branch && branch !== 'all')  { where.push('o.sucursal = ?'); params.push(branch); }
    const whereSQL = where.length ? 'WHERE ' + where.join(' AND ') : '';
    const limitNum = Math.min(Math.max(parseInt(limit) || 10, 1), 50);

    const [rows] = await db.execute(`
      SELECT p.nombre, p.marca, p.categoria, p.precio,
             SUM(oi.cantidad)        AS vendidos,
             SUM(oi.subtotal)        AS ingresos,
             COUNT(DISTINCT o.id)    AS num_pedidos
      FROM order_items oi
      JOIN products p ON p.id = oi.product_id
      JOIN orders   o ON o.id = oi.order_id
      ${whereSQL}
      GROUP BY p.nombre, p.marca, p.categoria, p.precio
      ORDER BY vendidos DESC
      LIMIT ${limitNum}
    `, params);

    res.json(rows);
  } catch (err) {
    console.error('Error top-products:', err);
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════════
// 🗂️ GET /api/admin/reports/by-category
// ══════════════════════════════════════════════════
router.get('/by-category', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const { from, to, branch } = req.query;

    const whereArr = [];
    const p = [];
    if (from)                        { whereArr.push('o.fecha >= ?');   p.push(from); }
    if (to)                          { whereArr.push('o.fecha <= ?');   p.push(to); }
    if (branch && branch !== 'all')  { whereArr.push('o.sucursal = ?'); p.push(branch); }
    const where = whereArr.length ? 'WHERE ' + whereArr.join(' AND ') : '';

    const [rows] = await db.execute(`
      SELECT
        COALESCE(p.categoria, 'Sin categoría') AS categoria,
        SUM(oi.cantidad)                        AS vendidos,
        SUM(oi.subtotal)                        AS ingresos,
        COUNT(DISTINCT p.id)                    AS productos_distintos
      FROM order_items oi
      JOIN orders   o ON o.id  = oi.order_id
      JOIN products p ON p.id  = oi.product_id
      ${where}
      GROUP BY p.categoria
      ORDER BY ingresos DESC
    `, p);

    res.json(rows);
  } catch (err) {
    console.error('Error by-category:', err);
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════════
// 🏪 GET /api/admin/reports/branch-detail/:id
// ══════════════════════════════════════════════════
router.get('/branch-detail/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const { id } = req.params;

    const [[branch]] = await db.execute(`
      SELECT b.*,
        COUNT(DISTINCT i.product_id)  AS productos,
        COALESCE(SUM(i.stock), 0)    AS stock_total,
        COALESCE(SUM(i.stock * p.precio), 0) AS valor_inventario,
        SUM(CASE WHEN i.stock <= i.min_stock AND i.stock > 0 THEN 1 ELSE 0 END) AS bajo_stock,
        SUM(CASE WHEN i.stock = 0 THEN 1 ELSE 0 END) AS sin_stock
      FROM branches b
      LEFT JOIN inventory i ON i.branch_id = b.id
      LEFT JOIN products  p ON p.id = i.product_id
      WHERE b.id = ?
      GROUP BY b.id
    `, [id]);

    if (!branch) return res.status(404).json({ error: 'Sucursal no encontrada' });

    const [[sales]] = await db.execute(`
      SELECT
        COUNT(o.id)               AS pedidos_mes,
        COALESCE(SUM(o.total), 0) AS ingresos_mes,
        COALESCE(AVG(o.total), 0) AS ticket_promedio,
        COUNT(DISTINCT o.user_id) AS clientes_unicos
      FROM orders o
      WHERE o.sucursal = ? AND DATE(o.fecha) >= DATE_SUB(NOW(), INTERVAL 30 DAY)
        AND o.status != 'cancelado'
    `, [id]).catch(() => [[{ pedidos_mes:0, ingresos_mes:0, ticket_promedio:0, clientes_unicos:0 }]]);

    const [topProds] = await db.execute(`
      SELECT p.nombre, p.categoria,
        SUM(oi.cantidad) AS vendidos,
        SUM(oi.subtotal) AS ingresos
      FROM order_items oi
      JOIN orders   o ON o.id  = oi.order_id
      JOIN products p ON p.id  = oi.product_id
      WHERE o.sucursal = ? AND o.status != 'cancelado'
        AND DATE(o.fecha) >= DATE_SUB(NOW(), INTERVAL 30 DAY)
      GROUP BY p.id, p.nombre, p.categoria ORDER BY vendidos DESC LIMIT 5
    `, [id]).catch(() => [[]]);

    const [lowStock] = await db.execute(`
      SELECT p.nombre, p.categoria, i.stock, i.min_stock
      FROM inventory i
      JOIN products p ON p.id = i.product_id
      WHERE i.branch_id = ? AND i.stock <= i.min_stock
      ORDER BY i.stock ASC LIMIT 5
    `, [id]);

    res.json({ branch, sales: sales || {}, topProds, lowStock });
  } catch (err) {
    console.error('Error branch-detail:', err);
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════════════════════════
// 🔮 GET /api/admin/reports/prediccion-agotamiento
//
// Predicción de agotamiento de inventario POR SUCURSAL usando el
// modelo de decrecimiento exponencial: S(t) = S₀ · e^(-k·t)
//
// Donde:
//   S₀ = stock actual de la sucursal para ese producto
//   k  = ventas_semanales / S₀  (constante de decrecimiento)
//   t  = tiempo en semanas
//
// Una fila por combinación producto + sucursal.
// Filtros: branch (id de sucursal), alerta, categoria
// ══════════════════════════════════════════════════════════════════
router.get('/prediccion-agotamiento', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const { branch, alerta, categoria } = req.query;

    // ── 1. Obtener inventario + ventas últimos 30 días, por producto·sucursal ──
    const whereArr = [];
    const params   = [];

    if (branch && branch !== 'all') {
      whereArr.push('i.branch_id = ?');
      params.push(branch);
    }
    if (categoria) {
      whereArr.push('p.categoria = ?');
      params.push(categoria);
    }

    const where = whereArr.length ? 'WHERE ' + whereArr.join(' AND ') : '';

    const [rows] = await db.execute(`
      SELECT
        p.id                                    AS product_id,
        p.nombre                                AS producto,
        p.categoria,
        p.marca,
        b.id                                    AS branch_id,
        COALESCE(b.nombre, b.id)               AS sucursal,
        i.stock                                 AS stock_actual,
        COALESCE(i.min_stock, 0)               AS min_stock,
        -- Ventas de este producto en esta sucursal en los últimos 30 días
        COALESCE(
          (SELECT SUM(oi2.cantidad)
           FROM order_items oi2
           JOIN orders o2 ON o2.id = oi2.order_id
           WHERE oi2.product_id = p.id
             AND o2.sucursal    = b.id
             AND o2.status     != 'cancelado'
             AND DATE(o2.fecha) >= DATE_SUB(NOW(), INTERVAL 30 DAY)
          ), 0
        )                                       AS ventas_30d
      FROM inventory i
      JOIN products p  ON p.id = i.product_id
      JOIN branches b  ON b.id = i.branch_id
      ${where}
      ORDER BY p.nombre ASC, b.id ASC
    `, params);

    // ── 2. Calcular modelo exponencial para cada fila ──────────────────────────
    const SEMANAS_MES = 4.33; // 30 / 7 = 4.2857 ≈ 4.33

    const resultado = rows.map(row => {
      const S0      = Number(row.stock_actual)  || 0;
      const v30     = Number(row.ventas_30d)    || 0;
      const Sc      = Number(row.min_stock)     || 0;

      // Tasa diaria y semanal
      const tasa_diaria  = +(v30 / 30).toFixed(3);
      const ventas_sem   = +(v30 / SEMANAS_MES).toFixed(2);

      // Constante de decrecimiento k (sem⁻¹)
      // k = ventas_semanales / S₀
      // Si S₀ = 0 no tiene sentido calcular k
      const k = S0 > 0 ? +(ventas_sem / S0).toFixed(4) : 0;

      // ── Semanas hasta nivel crítico: t = -ln(Sc/S0) / k ──
      let semanas_a_critico = null;
      if (S0 > 0 && S0 > Sc && k > 0) {
        semanas_a_critico = +(-Math.log(Sc / S0) / k).toFixed(2);
      }

      // ── Semanas hasta agotamiento total (S=1): t = ln(S0) / k ──
      let semanas_agotamiento = null;
      if (S0 > 1 && k > 0) {
        semanas_agotamiento = +(Math.log(S0) / k).toFixed(2);
      }

      // ── Días hasta agotamiento (modelo lineal complementario) ──
      const dias_lineales = tasa_diaria > 0 ? Math.round(S0 / tasa_diaria) : null;

      // ── Determinar nivel de alerta ──
      let alerta_nivel;
      if (S0 === 0) {
        alerta_nivel = 'agotado';
      } else if (v30 === 0) {
        alerta_nivel = 'sin_movimiento';
      } else if (S0 <= Sc) {
        alerta_nivel = 'critico';       // ya está en o bajo el mínimo
      } else if (semanas_a_critico !== null && semanas_a_critico <= 2) {
        alerta_nivel = 'critico';       // llega al mínimo en ≤ 2 semanas
      } else if (semanas_a_critico !== null && semanas_a_critico <= 4) {
        alerta_nivel = 'bajo';          // llega al mínimo en ≤ 4 semanas
      } else if (semanas_a_critico !== null && semanas_a_critico <= 8) {
        alerta_nivel = 'moderado';
      } else {
        alerta_nivel = 'ok';
      }

      // Proyección semanal (semanas 0, 1, 2, 4, 8, 12, 16, 20)
      const proyeccion = k > 0
        ? [0,1,2,4,8,12,16,20].map(t => ({
            semana: t,
            stock_estimado: Math.max(0, Math.round(S0 * Math.exp(-k * t)))
          }))
        : [];

      return {
        product_id:          row.product_id,
        producto:            row.producto,
        categoria:           row.categoria,
        marca:               row.marca,
        branch_id:           row.branch_id,
        sucursal:            row.sucursal,
        stock_actual:        S0,
        min_stock:           Sc,
        ventas_30d:          v30,
        tasa_diaria,
        ventas_semanales:    ventas_sem,
        k,
        semanas_a_critico,
        semanas_agotamiento,
        dias_lineales,
        alerta:              alerta_nivel,
        proyeccion,
      };
    });

    // ── 3. Filtrar por alerta si se solicitó ─────────────────────────────────
    const filtrado = alerta
      ? resultado.filter(r => r.alerta === alerta)
      : resultado;

    // ── 4. Ordenar: critico primero, luego bajo, moderado, ok, sin_movimiento ─
    const ORDEN = { agotado:0, critico:1, bajo:2, moderado:3, sin_movimiento:4, ok:5 };
    filtrado.sort((a, b) =>
      (ORDEN[a.alerta] ?? 9) - (ORDEN[b.alerta] ?? 9) ||
      (a.semanas_a_critico ?? 9999) - (b.semanas_a_critico ?? 9999)
    );

    res.json(filtrado);
  } catch (err) {
    console.error('Error prediccion-agotamiento:', err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;