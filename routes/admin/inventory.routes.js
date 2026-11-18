const express = require('express');
const router  = express.Router();

const { getDB }                      = require('../../config/db');
const { buildOrderFilter } = require('../../helpers/orderStats');
const {transferInventory}=require('../../helpers/inventoryTransfer');
const {mutateInventory}=require('../../helpers/inventoryMutation');
const {requireVariants,saveVariants,positive}=require('../../helpers/variantInventory');
const { authMiddleware, adminOnly }  = require('../../middlewares/auth');

// ================================
// 📦 GET /api/admin/inventory
// Usa la vista v_inventario_completo
// ================================

router.get('/', authMiddleware, adminOnly, async (req, res) => {
  const { branch, low_stock } = req.query;

  try {
    const db = await getDB();

    let sql    = `SELECT * FROM v_inventario_completo WHERE 1=1`;
    const params = [];

    if (branch && branch !== 'all') {
      sql += ' AND branch_id = ?';
      params.push(branch);
    }
    if (low_stock === 'true') {
      sql += " AND estado IN ('bajo_stock','sin_stock')";
    }

    sql += ' ORDER BY sucursal, producto';

    const [rows] = await db.execute(sql, params);
    res.json(rows);
  } catch (err) {
    console.error('Error obteniendo inventario:', err);
    res.status(500).json({ error: 'Error obteniendo inventario' });
  }
});

// ================================
// 📊 GET /api/admin/inventory/stats
// ================================

router.get('/stats', authMiddleware, adminOnly, async (req, res) => {
  try {
    const filter = buildOrderFilter({branch:req.query.branch});
    const branchId = filter.params[0];
    const where = branchId ? 'WHERE branch_id = ?' : '';
    const params = branchId ? [branchId] : [];
    const db = await getDB();

    const [stats] = await db.execute(`
      SELECT
        COUNT(DISTINCT product_id)                                          AS total_productos,
        COUNT(DISTINCT branch_id)                                           AS total_sucursales,
        SUM(stock)                                                          AS stock_total,
        SUM(CASE WHEN estado = 'sin_stock'  THEN 1 ELSE 0 END)             AS productos_sin_stock,
        SUM(CASE WHEN estado = 'bajo_stock' THEN 1 ELSE 0 END)             AS productos_bajo_stock,
        SUM(valor_stock)                                                    AS valor_inventario
      FROM v_inventario_completo ${where}
    `, params);

    const [porSucursal] = await db.execute(`
      SELECT
        sucursal,
        COUNT(DISTINCT product_id) AS productos,
        SUM(stock)                 AS stock_total,
        SUM(valor_stock)           AS valor_inventario
      FROM v_inventario_completo ${where}
      GROUP BY branch_id, sucursal
      ORDER BY valor_inventario DESC
    `, params);

    res.json({ general: stats[0], porSucursal });
  } catch (err) {
    console.error('Error obteniendo estadísticas de inventario:', err);
    res.status(err.statusCode || 500).json({ error: err.statusCode ? err.message : 'Error obteniendo estadísticas' });
  }
});

// ================================
// 📉 GET /api/admin/inventory/prediccion-agotamiento
// Algoritmo de decrecimiento lineal: T* = U₀ / r
// donde r = ventas_periodo / dias_periodo
// ⚠️  DEBE ir ANTES de /:id para que Express no lo confunda
// ================================

router.get('/prediccion-agotamiento', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const DIAS_PERIODO = 30;

    const [rows] = await db.execute(`
      SELECT
        i.id,
        i.product_id,
        i.branch_id,
        i.stock        AS stock_actual,
        i.min_stock,
        p.nombre       AS producto,
        p.categoria,
        b.nombre       AS sucursal,
        COALESCE(
          (
            SELECT SUM(oi.cantidad)
            FROM order_items oi
            JOIN orders o ON o.id = oi.order_id
            WHERE oi.product_id = i.product_id
              AND o.sucursal    = i.branch_id
              AND o.fecha      >= DATE_SUB(NOW(), INTERVAL ${DIAS_PERIODO} DAY)
              AND o.status NOT IN ('cancelado')
          ), 0
        ) AS ventas_periodo
      FROM inventory i
      JOIN products  p ON p.id = i.product_id
      JOIN branches  b ON b.id = i.branch_id
      WHERE p.activo = 1
      ORDER BY sucursal, producto
    `);

    const resultado = rows.map(row => {
      const r = row.ventas_periodo / DIAS_PERIODO; // tasa diaria (u/día)
      let dias_restantes   = null;
      let fecha_agotamiento = null;
      let mensaje          = null;
      let alerta           = 'ok';

      if (row.stock_actual === 0) {
        alerta  = 'agotado';
        mensaje = 'Sin stock';
      } else if (r <= 0) {
        alerta  = 'sin_movimiento';
        mensaje = 'Sin ventas recientes — no se puede predecir';
      } else {
        dias_restantes = Math.floor(row.stock_actual / r);
        const fecha = new Date();
        fecha.setDate(fecha.getDate() + dias_restantes);
        fecha_agotamiento = fecha.toISOString().slice(0, 10);
        mensaje = `Este producto se agotará en aproximadamente ${dias_restantes} días`;

        if      (dias_restantes <= 7)  alerta = 'critico';
        else if (dias_restantes <= 15) alerta = 'bajo';
        else if (dias_restantes <= 30) alerta = 'moderado';
      }

      return {
        ...row,
        tasa_diaria:      parseFloat(r.toFixed(2)),
        dias_restantes,
        fecha_agotamiento,
        mensaje,
        alerta,
      };
    });

    // Ordenar por urgencia
    const orden = { agotado: 0, critico: 1, bajo: 2, moderado: 3, sin_movimiento: 4, ok: 5 };
    resultado.sort((a, b) => orden[a.alerta] - orden[b.alerta]);

    res.json(resultado);
  } catch (err) {
    console.error('Error predicción agotamiento:', err.message);
    res.status(500).json({ error: 'Error calculando predicción', detalle: err.message });
  }
});

// ================================
// ➕ POST /api/admin/inventory
// ================================

router.post('/', authMiddleware, adminOnly, async(req,res)=>{
 try{res.json(await mutateInventory(await getDB(),{input:req.body,action:'crear',actor:req.user}));}
 catch(error){res.status(error.statusCode||500).json({error:error.statusCode?error.message:'No se pudo crear el inventario.'});}
});

// ================================
// ✏️ PUT /api/admin/inventory/:id
// ================================

router.put('/:id([0-9]+)', authMiddleware, adminOnly, async(req,res)=>{
 try{res.json(await mutateInventory(await getDB(),{id:req.params.id,input:req.body,action:'actualizar',actor:req.user}));}
 catch(error){res.status(error.statusCode||500).json({error:error.statusCode?error.message:'No se pudo actualizar el inventario.'});}
});

// ================================
// 🗑️ DELETE /api/admin/inventory/:id
// ================================

router.delete('/:id', authMiddleware, adminOnly, async(req,res)=>{
 try{res.json(await mutateInventory(await getDB(),{id:req.params.id,action:'eliminar',actor:req.user}));}
 catch(error){res.status(error.statusCode||500).json({error:error.statusCode?error.message:'No se pudo eliminar el inventario.'});}
});

// ================================
// 🔄 POST /api/admin/inventory/transfer
// ================================

router.post('/transfer', authMiddleware, adminOnly, async (req, res) => {
  try {res.json(await transferInventory(await getDB(),req.body,req.user));}
  catch(error){console.error('Error en transferencia:',error.message);res.status(error.statusCode||500).json({error:error.statusCode?error.message:'No se pudo completar la transferencia.'});}
});

// ================================
// ➕ POST /api/admin/inventory/batch
// ================================

router.post('/batch', authMiddleware, adminOnly, async(req,res)=>{
 if(!Array.isArray(req.body.items)||!req.body.items.length||req.body.items.length>500)return res.status(400).json({error:'Envía entre 1 y 500 registros.'});
 try{
 const db=await getDB();let created=0,updated=0;const details=[];
 for(const input of req.body.items){try{
  const [existing]=await db.execute('SELECT id FROM inventory WHERE product_id=? AND branch_id=?',[positive(input.product_id),positive(input.branch_id)]);
  await mutateInventory(db,{id:existing[0]?.id,input,action:existing.length?'actualizar':'crear',actor:req.user});existing.length?updated++:created++;
 }catch(error){details.push({product_id:input.product_id,error:error.statusCode?error.message:'No se pudo guardar el registro.'});}}
 res.json({created,updated,errors:details.length,details,total:req.body.items.length});
 }catch(error){res.status(503).json({error:'No se pudo conectar con el inventario. Intenta nuevamente.'});}
});

// ================================
// ✏️ PUT /api/admin/inventory/batch-update
// ================================

router.put('/batch-update', authMiddleware, adminOnly, async(req,res)=>{
 if(!Array.isArray(req.body.items)||!req.body.items.length||req.body.items.length>500)return res.status(400).json({error:'Envía entre 1 y 500 registros.'});
 try{
 const db=await getDB();let updated=0;const details=[];
 for(const input of req.body.items){try{await mutateInventory(db,{id:input.id,input,action:'actualizar',actor:req.user});updated++;}catch(error){details.push({id:input.id,error:error.statusCode?error.message:'No se pudo guardar el registro.'});}}
 res.json({updated,errors:details.length,details,total:req.body.items.length});
 }catch(error){res.status(503).json({error:'No se pudo conectar con el inventario. Intenta nuevamente.'});}
});

router.get('/:id/variantes',authMiddleware,adminOnly,async(req,res)=>{
 try{requireVariants();const id=positive(req.params.id),db=await getDB();
  const [[inventory]]=await db.execute('SELECT i.*,p.talla,p.colores,p.nombre AS producto FROM inventory i JOIN products p ON p.id=i.product_id WHERE i.id=?',[id]);
  if(!inventory)return res.status(404).json({error:'Inventario no encontrado.'});
  const [variantes]=await db.execute('SELECT id,talla,color,stock FROM inventario_variantes WHERE inventario_id=? ORDER BY id',[id]);res.json({inventory,variantes});
 }catch(error){res.status(error.statusCode||500).json({error:error.statusCode?error.message:'No se pudieron consultar las variantes.'});}
});
router.put('/:id/variantes',authMiddleware,adminOnly,async(req,res)=>{
 try{res.json(await saveVariants(await getDB(),req.params.id,req.body.variantes,req.user));}
 catch(error){res.status(error.statusCode||500).json({error:error.statusCode?error.message:'No se pudieron guardar las variantes.'});}
});
module.exports = router;
