// Comprueba las rutas reales y sus consultas con un adaptador aislado, sin MySQL.
const assert=require('node:assert/strict'),express=require('express'),jwt=require('jsonwebtoken');
process.env.JWT_SECRET='isolated-admin-stats-secret';
const {buildOrderFilter}=require('../helpers/orderStats');
const orders=[
 {id:1,sucursal:1,fecha:'2026-10-14T00:00:00.000Z',status:'pendiente',total:100},
 {id:2,sucursal:1,fecha:'2026-10-14T12:00:00.000Z',status:'preparando',total:200},
 {id:3,sucursal:1,fecha:'2026-10-14T23:59:59.999Z',status:'en_camino',total:300},
 {id:4,sucursal:1,fecha:'2026-10-14T15:00:00.000Z',status:'cancelado',total:900},
 {id:5,sucursal:2,fecha:'2026-10-14T16:00:00.000Z',status:'procesando',total:400},
 {id:6,sucursal:1,fecha:'2026-10-15T00:00:00.000Z',status:'entregado',total:700},
 {id:7,sucursal:1,fecha:'2026-10-13T15:00:00.000Z',status:'enviado',total:600},
 {id:8,sucursal:1,fecha:'2026-10-14T23:59:59.000Z',status:'enviado',total:50},
];
let calls=[];
const db={execute:async(sql,params=[])=>{
 calls.push({sql,params});
 if(sql==='SELECT id,nombre FROM branches ORDER BY nombre')return [[{id:1,nombre:'Centro'},{id:2,nombre:'Norte'}]];
 if(sql.includes('v_inventario_completo')){
  if(sql.includes('WHERE branch_id'))assert.deepEqual(params,[1]);
  if(sql.includes('AS stock_total'))return [[{stock_total:8,productos_sin_stock:1,productos_bajo_stock:1}]];
  assert.ok(sql.includes("estado IN ('bajo_stock','sin_stock')"));return [[{stock:0,estado:'sin_stock'}]];
 }
 let rows=orders.slice(),i=0;
 if(sql.includes('o.fecha >= ?')){const from=params[i++];rows=rows.filter(row=>row.fecha.slice(0,10)>=from);}
 if(sql.includes('DATE_ADD(?, INTERVAL 1 DAY)')){const to=params[i++];rows=rows.filter(row=>row.fecha.slice(0,10)<=to);}
 if(sql.includes('o.sucursal = ?')){const branch=params[i++];rows=rows.filter(row=>row.sucursal===Number(branch));}
 if(sql.includes('AS total_ordenes')){
  assert.ok(sql.includes("('preparando','procesando')"));assert.ok(sql.includes("('en_camino','enviado')"));assert.ok(sql.includes("CASE WHEN o.status <> 'cancelado' THEN o.total"));
  const active=rows.filter(row=>row.status!=='cancelado'),sum=active.reduce((total,row)=>total+row.total,0);
  return [[{total_ordenes:rows.length,ingresos_totales:sum,ticket_promedio:sum/(active.length||1),pendientes:rows.filter(row=>row.status==='pendiente').length,preparando:rows.filter(row=>['preparando','procesando'].includes(row.status)).length,en_camino:rows.filter(row=>['en_camino','enviado'].includes(row.status)).length,entregadas:rows.filter(row=>row.status==='entregado').length,canceladas:rows.filter(row=>row.status==='cancelado').length}]];
 }
 if(sql.includes("AND o.status <> 'cancelado'"))rows=rows.filter(row=>row.status!=='cancelado');
 if(sql.includes('JOIN products'))return [[{nombre:'Producto',vendidos:rows.length,ingresos:rows.reduce((sum,row)=>sum+row.total,0)}]];
 if(sql.includes('GROUP BY dia'))return [[{dia:'2026-10-14',total:rows.reduce((sum,row)=>sum+row.total,0)}]];
 if(sql.includes('GROUP BY o.sucursal'))return [[{branch_id:1,sucursal:'Centro',ingresos:rows.filter(row=>row.status!=='cancelado').reduce((sum,row)=>sum+row.total,0)}]];
 if(sql.includes("AND o.status IN ('preparando','procesando')"))rows=rows.filter(row=>['preparando','procesando'].includes(row.status));
 return [rows.sort((a,b)=>b.fecha.localeCompare(a.fecha)).slice(0,6)];
}};
const dbPath=require.resolve('../config/db');require.cache[dbPath]={id:dbPath,filename:dbPath,loaded:true,exports:{getDB:async()=>db}};
async function main(){
 assert.ok(buildOrderFilter({to:'2024-02-29'}).where.includes('DATE_ADD'));
 for(const query of [{to:'2026-02-29'},{from:'2026-10-15',to:'2026-10-14'},{branch:'Centro'},{branch:'1 OR 1=1'}])assert.throws(()=>buildOrderFilter(query));
 const app=express();app.use('/api/admin/dashboard',require('../routes/admin/dashboard.routes'));app.use('/api/admin/orders',require('../routes/admin/orders.routes'));app.use('/api/admin/inventory',require('../routes/admin/inventory.routes'));
 const server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));const base='http://127.0.0.1:'+server.address().port;
 const headers={Authorization:'Bearer '+jwt.sign({id:1,rol:'admin'},process.env.JWT_SECRET)};
 try{
  assert.equal((await fetch(base+'/api/admin/dashboard')).status,401);
  const filter='?from=2026-10-14&to=2026-10-14&branch=1';
  const response=await fetch(base+'/api/admin/dashboard'+filter,{headers});assert.equal(response.status,200);const data=await response.json();
  assert.equal(data.resumen.total_ordenes,5);assert.equal(data.resumen.ingresos_totales,650);assert.equal(data.resumen.preparando,1);assert.equal(data.resumen.en_camino,2);assert.equal(data.resumen.canceladas,1);assert.equal(data.salesTimeline[0].total,650);assert.equal(data.topProducts[0].ingresos,650);assert.equal(data.branches.length,2);assert.equal(data.recentOrders.length,5);assert.ok(data.recentOrders.some(row=>row.id===3));
  for(const call of calls.filter(call=>call.sql.includes('FROM orders o')||call.sql.includes('FROM order_items'))){assert.ok(call.sql.includes('DATE_ADD'));assert.deepEqual(call.params,['2026-10-14','2026-10-14',1]);}
  const summary=await (await fetch(base+'/api/admin/orders/stats/summary'+filter,{headers})).json();assert.deepEqual(summary.resumen,data.resumen);assert.equal(summary.resumen.procesando,1);assert.equal(summary.resumen.enviado,2);
  const list=await (await fetch(base+'/api/admin/orders'+filter+'&status=preparando',{headers})).json();assert.deepEqual(list.map(row=>row.id),[2]);
  const inventory=await (await fetch(base+'/api/admin/inventory/stats?branch=1',{headers})).json();assert.equal(inventory.general.stock_total,8);
  assert.equal((await (await fetch(base+'/api/admin/inventory?low_stock=true&branch=1',{headers})).json())[0].estado,'sin_stock');
  const before=calls.length;assert.equal((await fetch(base+'/api/admin/dashboard?to=2026-02-30',{headers})).status,400);assert.equal(calls.length,before);
  console.log('ESTADÍSTICAS OK: filtros compartidos, día final completo, sucursal por ID, estados actuales/antiguos, cancelaciones excluidas de importes y alertas sin stock. Sin BD real.');
 }finally{await new Promise(resolve=>server.close(resolve));}
}
main().catch(error=>{console.error(error);process.exitCode=1;});
