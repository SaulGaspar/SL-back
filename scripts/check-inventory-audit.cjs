// Pruebas aisladas de lógica y rutas. Sin consultas a una base de datos real.
const assert=require('node:assert/strict');
process.env.SPORTLIKE_VARIANTS_ENABLED='true';
process.env.SPORTLIKE_AUDIT_ENABLED='true';
process.env.JWT_SECRET='isolated-inventory-audit';
const {saveVariants,allocateVariant,deductVariant,restoreVariant}=require('../helpers/variantInventory');
const {mutateInventory,saveProductInventory}=require('../helpers/inventoryMutation');
const {transferInventory}=require('../helpers/inventoryTransfer');
const {changeOrderStatus}=require('../helpers/orderStatus');
const {auditedTransaction}=require('../helpers/audit');

function memory(){
 const state={inventory:[{id:1,product_id:7,branch_id:1,stock:5,min_stock:0},{id:2,product_id:7,branch_id:2,stock:0,min_stock:0}],variants:[],audit:[],commits:0,rollbacks:0,released:0,failAudit:false,order:{id:9,status:'pendiente',sucursal:1},user:{id:3,usuario:'operador',rol:'admin',verificado:1}};
 let snapshot;
 const conn={beginTransaction:async()=>{snapshot=structuredClone(state);},commit:async()=>{state.commits++;},rollback:async()=>{const failures=state.rollbacks+1;Object.assign(state,snapshot,{rollbacks:failures});},release:()=>{state.released++;},execute:async(sql,p=[])=>{
  if(sql.startsWith('INSERT INTO historial_admin')){if(state.failAudit)throw Error('Historial no disponible');state.audit.push(p);return [{insertId:state.audit.length}];}
  if(sql.includes('FROM branches WHERE id IN'))return [[{id:1,activo:1},{id:2,activo:1}]];
  if(sql.includes('FROM branches'))return [[{id:2,activo:1}]];
  if(sql.includes('SELECT id, activo FROM products'))return [[{id:7,activo:1}]];
  if(sql.startsWith('SELECT i.*, p.talla')){assert.match(sql,/FOR UPDATE/);return [[{...state.inventory.find(r=>r.id===p[0]),talla:'26,27',colores:'Negro,Blanco'}]];}
  if(sql.startsWith('SELECT * FROM inventory WHERE id='))return [[state.inventory.find(r=>r.id===p[0])]];
  if(sql.startsWith('SELECT * FROM inventory WHERE product_id='))return [[state.inventory.find(r=>r.product_id===p[0]&&r.branch_id===p[1])]];
  if(sql.startsWith('SELECT id, branch_id, stock'))return [[...state.inventory]];
  if(sql.startsWith('SELECT id FROM inventory WHERE product_id='))return [[{id:1}]];
  if(sql.startsWith('SELECT i.id AS inventory_id')){
   assert.match(sql,/FOR UPDATE/);
   const v=state.variants.find(v=>v.talla===p[1]&&v.color===p[2]&&v.stock>=p[3]);
   return [v?[{inventory_id:v.inventario_id,variant_id:v.id,branch_id:v.inventario_id,nombre:'Centro',stock:v.stock,precio:500}]:[]];
  }
  if(sql.startsWith('SELECT id,inventario_id'))return [[...state.variants]];
  if(sql.startsWith('SELECT id,talla,color,stock')||sql.startsWith('SELECT id FROM inventario_variantes'))return [state.variants.filter(v=>v.inventario_id===p[0]&&(p.length===1||(v.talla===p[1]&&v.color===p[2])))];
  if(sql.startsWith('INSERT INTO inventario_variantes')){
   const [id,talla,color,stock]=p,old=state.variants.find(v=>v.inventario_id===id&&v.talla===talla&&v.color===color);
   if(old)old.stock=sql.includes('stock=stock+')?old.stock+stock:stock;
   else state.variants.push({id:state.variants.length+1,inventario_id:id,talla,color,stock});return [{affectedRows:1}];
  }
  if(sql.startsWith('UPDATE inventario_variantes SET stock=stock-')){const v=state.variants.find(v=>v.id===p[1]);if(!v||v.stock<p[0])return [{affectedRows:0}];v.stock-=p[0];return [{affectedRows:1}];}
  if(sql.startsWith('UPDATE inventario_variantes SET stock=stock+')){state.variants.find(v=>v.id===p[1]).stock+=p[0];return [{affectedRows:1}];}
  if(sql.startsWith('UPDATE inventory SET stock = stock -')){const v=state.inventory.find(v=>v.id===p[1]);if(v.stock<p[0])return [{affectedRows:0}];v.stock-=p[0];return [{affectedRows:1}];}
  if(sql.startsWith('UPDATE inventory SET stock = stock +')){state.inventory.find(v=>v.id===p[1]).stock+=p[0];return [{affectedRows:1}];}
  if(sql.startsWith('UPDATE inventory SET stock=')){const v=state.inventory.find(v=>v.id===p.at(-1));v.stock=p[0];return [{affectedRows:1}];}
  if(sql.startsWith('INSERT INTO inventory')){state.inventory.find(v=>v.product_id===p[0]&&v.branch_id===p[1]).stock+=p[2];return [{affectedRows:1}];}
  if(sql.startsWith('SELECT id, status, sucursal'))return [[{...state.order}]];
  if(sql.includes('FROM order_items'))return [[{product_id:7,talla:'26',color:'Negro',cantidad:1}]];
  if(sql.startsWith('UPDATE orders SET status')){state.order.status=p[0];return [{affectedRows:1}];}
  if(sql.includes('(usuario = ? OR telefono = ?)'))return [[]];
  if(sql.startsWith('SELECT id, rol, verificado FROM users'))return [[{...state.user}]];
  if(sql.startsWith('SELECT id,rol,verificado FROM users'))return [[{...state.user}]];
  if(sql.includes('lockedUntil, usuario FROM users'))return [[{...state.user}]];
  if(sql.includes('UPDATE users SET nombre')){state.user.rol=p[5];state.user.verificado=p[6];return [{affectedRows:1}];}
  if(sql.startsWith('UPDATE users SET verificado')){state.user.verificado=0;return [{affectedRows:1}];}
  if(sql.includes('FROM historial_admin'))return [[...state.audit.map((v,i)=>({id:i+1,usuario:v[1],accion:v[2],entidad:v[3],antes:v[5],despues:v[6]}))]];
  throw Error('SQL sin simular: '+sql);
 }};
 return {state,conn,db:{getConnection:async()=>conn,execute:conn.execute}};
}
const actor={id:3,usuario:'operador'};
async function test(){
 let {db,state,conn}=memory();
 const rows=[{talla:'26',color:'Negro',stock:2},{talla:'27',color:'Blanco',stock:3}];
 await assert.rejects(()=>saveVariants(db,1,[{...rows[0],stock:4}],actor),/primer desglose/);
 assert.equal(state.variants.length,0);assert.equal(state.inventory[0].stock,5);
 await saveVariants(db,1,rows,actor);assert.equal(state.audit.length,1);assert.equal(state.audit[0][0],3);assert.equal(JSON.parse(state.audit[0][6]).total,5);
 await assert.rejects(()=>saveVariants(db,1,[rows[0],rows[0]],actor),/repetidas/);
 await assert.rejects(()=>saveVariants(db,1,[{...rows[0],stock:-1},rows[1]],actor),/enteros/);
 await assert.rejects(()=>saveVariants(db,1,[rows[0]],actor),/Conserva/);
 await assert.rejects(()=>saveVariants(db,1,[{...rows[0],talla:'99'},rows[1]],actor),/no pertenece/);
 await assert.rejects(()=>mutateInventory(db,{id:1,input:{stock:100},action:'actualizar',actor}),/talla\/color/);
 await assert.rejects(()=>saveProductInventory(conn,7,[{branch_id:1,stock:100}],actor),/Talla y color/);
 await assert.rejects(()=>allocateVariant(conn,{product_id:7,talla:'26',color:'Blanco',cantidad:1}),/no están disponibles/);
 const allocation=await allocateVariant(conn,{product_id:7,talla:'26',color:'Negro',cantidad:2});assert.equal(allocation.variant_id,1);
 await assert.rejects(()=>auditedTransaction(db,{actor,action:'test',entity:'inventario'},async c=>{await deductVariant(c,{variant_id:1,cantidad:3});return {};}),/disponibilidad/);
 assert.equal(state.variants[0].stock,2);
 await transferInventory(db,{product_id:7,from_branch_id:1,to_branch_id:2,cantidad:1,talla:'26',color:'Negro'},actor);
 assert.deepEqual(state.inventory.map(v=>v.stock),[4,1]);assert.equal(state.variants.find(v=>v.inventario_id===2).stock,1);assert.equal(state.variants[1].stock,3);
 state.failAudit=true;const previous=structuredClone(state.inventory);
 await assert.rejects(()=>saveVariants(db,1,[{...rows[0],stock:0},rows[1]],actor),/Historial/);assert.deepEqual(state.inventory,previous);assert.equal(state.variants[0].stock,1);
 state.failAudit=false;
 await changeOrderStatus(db,9,'cancelado',true,actor);assert.equal(state.variants[0].stock,2);assert.equal(state.inventory[0].stock,5);
 await changeOrderStatus(db,9,'cancelado',true,actor);assert.equal(state.inventory[0].stock,5);
 await assert.rejects(()=>restoreVariant(conn,1,{talla:'histórica',color:null,cantidad:1}),/pedido histórico/);
 const secret='contraseña-no-auditable';state.user.password=secret;
 const dbPath=require.resolve('../config/db');require.cache[dbPath]={id:dbPath,filename:dbPath,loaded:true,exports:{getDB:async()=>db}};
 const express=require('express'),jwt=require('jsonwebtoken'),app=express();app.use(express.json());app.use('/users',require('../routes/admin/users.routes'));app.use('/history',require('../routes/admin/history.routes'));app.use('/inventory',require('../routes/admin/inventory.routes'));
 const server=app.listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));const base='http://127.0.0.1:'+server.address().port;
 const headers={'Content-Type':'application/json',Authorization:'Bearer '+jwt.sign({id:3,rol:'admin'},process.env.JWT_SECRET)};
 try{
  let response=await fetch(base+'/users/10',{method:'PUT',headers,body:JSON.stringify({nombre:'Ana',apellidoP:'Prueba',usuario:'ana_prueba',rol:'cliente',verificado:1})});assert.equal(response.status,200);
  const audit=state.audit.at(-1);assert.equal(audit[2],'actualizar_permisos');assert.deepEqual(JSON.parse(audit[5]),{rol:'admin',verificado:1});assert.deepEqual(JSON.parse(audit[6]),{rol:'cliente',verificado:1});assert.ok(!JSON.stringify(state.audit).includes(secret));
  state.user.rol='admin';response=await fetch(base+'/history',{headers});assert.equal(response.status,200);assert.ok((await response.json()).rows.length);
  assert.equal((await fetch(base+'/users/3',{method:'DELETE',headers})).status,400);
  assert.equal((await fetch(base+'/users/10',{method:'DELETE',headers})).status,200);assert.equal(state.audit.at(-1)[2],'desactivar_cuenta');state.user.verificado=1;
  response=await fetch(base+'/inventory/batch-update',{method:'PUT',headers,body:JSON.stringify({items:[{id:1,stock:5,min_stock:0}]})});assert.equal(response.status,200);assert.equal((await response.json()).updated,1,'La ruta batch-update no queda atrapada por /:id');
  assert.equal((await fetch(base+'/history?entidad=hack',{headers})).status,400);assert.equal((await fetch(base+'/history')).status,401);assert.equal((await fetch(base+'/history',{method:'DELETE',headers})).status,404);
 }finally{await new Promise(r=>server.close(r));}
 console.log('INVENTARIO Y AUDITORÍA OK: desglose inicial exacto, combinaciones válidas, aislamiento por talla/color, transferencia, cancelación única, bloqueo de totales, rollback si falla historial, permisos auditados sin secretos e historial protegido. BD simulada.');
}
test().catch(e=>{console.error(e);process.exitCode=1;});
