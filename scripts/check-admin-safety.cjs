// Prueba aislada. No conecta con MySQL, Google ni Mercado Pago.
const assert=require('node:assert/strict'),express=require('express'),jwt=require('jsonwebtoken');
process.env.JWT_SECRET='isolated-admin-safety';
const {transferInventory}=require('../helpers/inventoryTransfer');
const {changeOrderStatus,allowedOrderStatuses}=require('../helpers/orderStatus');

function memoryDB(){
 const state={stock:{1:5,2:0},order:{id:91,status:'pendiente',sucursal:1,pedido_ref:'MP-123'},items:[{product_id:7,cantidad:2}],fail:false,commits:0,rollbacks:0,releases:0,sql:[]};
 let tail=Promise.resolve();
 const db={execute:async()=>{throw Error('No se debe usar el pool dentro de una transacción');},getConnection:async()=>{
  let unlock,snapshot;
  return {
   beginTransaction:async()=>{const previous=tail;tail=new Promise(resolve=>{unlock=resolve;});await previous;snapshot=JSON.stringify({stock:state.stock,order:state.order});},
   commit:async()=>{state.commits++;},rollback:async()=>{state.rollbacks++;Object.assign(state,JSON.parse(snapshot));},release:()=>{state.releases++;unlock?.();},
   execute:async(sql,params)=>{
    state.sql.push(sql);
    if(sql.includes('FROM branches')){assert.ok(sql.includes('FOR UPDATE'));return [[{id:1,activo:1},{id:2,activo:1}]];}
    if(sql.includes('FROM products')){assert.ok(sql.includes('FOR UPDATE'));return [[{id:7,activo:1}]];}
    if(sql.startsWith('SELECT id, branch_id, stock')){assert.ok(sql.includes('FOR UPDATE'));return [[{id:1,branch_id:1,stock:state.stock[1]},{id:2,branch_id:2,stock:state.stock[2]}]];}
    if(sql.startsWith('UPDATE inventory SET stock = stock -')){const [quantity,id]=params;if(state.stock[id]<quantity)return [{affectedRows:0}];state.stock[id]-=quantity;return [{affectedRows:1}];}
    if(sql.startsWith('UPDATE inventory SET stock = stock +')){if(state.fail)throw Error('Fallo simulado en destino');state.stock[params[1]]+=params[0];return [{affectedRows:1}];}
    if(sql.startsWith('SELECT id, status, sucursal')){assert.ok(sql.includes('FOR UPDATE'));return [[{...state.order}]];}
    if(sql.includes('FROM order_items'))return [[...state.items]];
    if(sql.startsWith('INSERT INTO inventory')){if(state.fail)throw Error('Fallo simulado al restituir');state.stock[params[1]]+=params[2];return [{affectedRows:1}];}
    if(sql.startsWith('UPDATE orders SET status')){state.order.status=params[0];return [{affectedRows:1}];}
    throw Error('SQL inesperado: '+sql);
   }
  };
 }};
 return {db,state};
}
async function testTransactions(){
 let {db,state}=memoryDB();
 await assert.rejects(()=>transferInventory(db,{product_id:7,from_branch_id:'1',to_branch_id:1,cantidad:1}),/misma sucursal/);
 await assert.rejects(()=>transferInventory(db,{product_id:7,from_branch_id:1,to_branch_id:2,cantidad:1.5}),/enteros/);
 const input={product_id:7,from_branch_id:1,to_branch_id:2,cantidad:4};
 const results=await Promise.allSettled([transferInventory(db,input),transferInventory(db,input)]);
 assert.equal(results.filter(result=>result.status==='fulfilled').length,1);assert.deepEqual(state.stock,{1:1,2:4});assert.equal(state.releases,2);
 ({db,state}=memoryDB());state.fail=true;await assert.rejects(()=>transferInventory(db,input),/Fallo simulado/);assert.deepEqual(state.stock,{1:5,2:0});assert.equal(state.rollbacks,1);
 ({db,state}=memoryDB());
 assert.deepEqual(allowedOrderStatuses('procesando'),['en_camino','cancelado']);
 await assert.rejects(()=>changeOrderStatus(db,91,'entregado'),/No se puede/);
 await assert.rejects(()=>changeOrderStatus(db,91,'cancelado',false),/Confirma/);
 const cancelled=await Promise.all([changeOrderStatus(db,91,'cancelado',true),changeOrderStatus(db,91,'cancelado',true)]);
 assert.equal(cancelled.filter(result=>result.inventoryRestored).length,1);assert.equal(state.stock[1],7);assert.equal(state.order.status,'cancelado');
 await assert.rejects(()=>changeOrderStatus(db,91,'pendiente'),/No se puede/);
 ({db,state}=memoryDB());state.order.status='en_camino';await assert.rejects(()=>changeOrderStatus(db,91,'cancelado',true),/No se puede/);await changeOrderStatus(db,91,'entregado');assert.equal(state.order.status,'entregado');
 ({db,state}=memoryDB());state.fail=true;await assert.rejects(()=>changeOrderStatus(db,91,'cancelado',true),/Fallo simulado/);assert.equal(state.order.status,'pendiente');assert.equal(state.stock[1],5);
}
async function testPermissionsAndAlias(){
 let current={id:7,rol:'admin',verificado:1,lockedUntil:null},fail=false,paidCalls=[],userUpdates=[];
 const pool={execute:async(sql,params)=>{if(fail)throw Error('Sin conexión');if(sql.includes('(usuario = ? OR telefono = ?)'))return [[]];if(sql.includes('UPDATE users SET nombre')){userUpdates.push(params);return [{affectedRows:1}];}return [current?[current]:[]];}};
 pool.getConnection=async()=>({...pool,beginTransaction:async()=>{},commit:async()=>{},rollback:async()=>{},release:()=>{}});
 const dbPath=require.resolve('../config/db');require.cache[dbPath]={id:dbPath,filename:dbPath,loaded:true,exports:{getDB:async()=>pool}};
 const paidPath=require.resolve('../helpers/createPaidOrder');require.cache[paidPath]={id:paidPath,filename:paidPath,loaded:true,exports:{createPaidOrder:async args=>{paidCalls.push(args);return {orderId:91};}}};
 const mpPath=require.resolve('../helpers/mercadoPago');require.cache[mpPath]={id:mpPath,filename:mpPath,loaded:true,exports:{getApprovedPaymentForUser:async id=>({id,status:'approved'})}};
 const {authMiddleware,adminOnly}=require('../middlewares/auth');const app=express();app.use(express.json());app.get('/sensitive',authMiddleware,adminOnly,(_req,res)=>res.json({ok:true}));app.use('/orders',require('../routes/admin/orders.routes'));app.use('/users',require('../routes/admin/users.routes'));
 const server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));const base='http://127.0.0.1:'+server.address().port;
 const headers={Authorization:'Bearer '+jwt.sign({id:7,rol:'admin'},process.env.JWT_SECRET),'Content-Type':'application/json'};
 try{
  assert.equal((await fetch(base+'/sensitive',{headers})).status,200);
  current.rol='cliente';assert.equal((await fetch(base+'/sensitive',{headers})).status,403);
  current.rol='admin';current.verificado=0;assert.equal((await fetch(base+'/sensitive',{headers})).status,403);
  current.verificado=1;current.lockedUntil=new Date(Date.now()+60000);assert.equal((await fetch(base+'/sensitive',{headers})).status,403);
  current=null;assert.equal((await fetch(base+'/sensitive',{headers})).status,403);
  fail=true;assert.equal((await fetch(base+'/sensitive',{headers})).status,503);
  const body={payment_id:'123',direccion_id:1,items:[{product_id:7,cantidad:1,talla:'27',color:'Negro'}]};
  const response=await fetch(base+'/orders',{method:'POST',headers,body:JSON.stringify(body)});assert.equal(response.status,200);assert.equal(paidCalls.length,1);assert.deepEqual(paidCalls[0].items,body.items);
  fail=false;current={id:7,rol:'admin',verificado:1};const user={nombre:'Ana',apellidoP:'Prueba',usuario:'ana_prueba'};
  const edit=payload=>fetch(base+'/users/7',{method:'PUT',headers,body:JSON.stringify(payload)});
  assert.equal((await edit({...user,rol:'cliente'})).status,400);assert.equal((await edit({...user,verificado:0})).status,400);
  assert.equal((await edit(user)).status,200);assert.equal(userUpdates[0][5],'admin');assert.equal(userUpdates[0][6],1);
 }finally{await new Promise(resolve=>server.close(resolve));}
}
(async()=>{await testTransactions();await testPermissionsAndAlias();console.log('ADMIN SEGURO OK: transferencias atómicas, rollback, bloqueos, concurrencia simulada, cancelación única con restitución, estados válidos, permisos vigentes y creación delegada. Sin BD ni pagos reales.');})().catch(error=>{console.error(error);process.exitCode=1;});
