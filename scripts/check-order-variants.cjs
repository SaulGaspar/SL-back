// Prueba aislada: no conecta con MySQL ni con Mercado Pago.
const assert=require('node:assert/strict'),express=require('express'),jwt=require('jsonwebtoken'),crypto=require('node:crypto');
process.env.JWT_SECRET='isolated-order-variant-test';process.env.MP_ACCESS_TOKEN='TEST-isolated';
let columns=true,preferenceCalls=0,preferenceBody,stock=8;const saved=[],decrements=[];
const product={id:1,nombre:'Tenis prueba',precio:500,descripcion:'Prueba',talla:'26,27',colores:'Negro,Blanco'};
const db={execute:async(sql,params=[])=>{
 if(sql==='SHOW COLUMNS FROM order_items')return [columns?[{Field:'talla'},{Field:'color'}]:[]];
 if(sql.includes('GET_LOCK'))return [[{acquired:1}]];
 if(sql.includes('RELEASE_LOCK'))return [[{released:1}]];
 if(sql.includes('FROM orders o'))return [[]];
 if(sql.includes('FROM direcciones'))return [[{id:1}]];
 if(sql.includes('SELECT id, nombre, descripcion'))return [[product]];
 if(sql.includes('MAX(i.stock)'))return [[{product_id:1,max_stock:stock}]];
 if(sql.includes('FROM users'))return [[{correo:'test@example.test',nombre:'Prueba'}]];
 if(sql.includes('FOR UPDATE'))return [params[1]<=stock?[{branch_id:1,nombre:'Sucursal prueba',stock,precio:500}]:[]];
 if(sql.startsWith('INSERT INTO orders'))return [{insertId:91}];
 if(sql.includes('INSERT INTO order_items')){saved.push(params);return [{insertId:saved.length}];}
 if(sql.includes('UPDATE inventory')){decrements.push(params);return [{affectedRows:1}];}
 if(sql.includes('SELECT nombre FROM products'))return [[product]];
 throw new Error('SQL no esperado: '+sql);
},getConnection:async()=>({...db,beginTransaction:async()=>{},commit:async()=>{},rollback:async()=>{},release:()=>{}})};
const dbPath=require.resolve('../config/db');require.cache[dbPath]={id:dbPath,filename:dbPath,loaded:true,exports:{getDB:async()=>db}};
const sdkPath=require.resolve('mercadopago'),sdk=require(sdkPath);
require.cache[sdkPath].exports={...sdk,Preference:class{async create({body}){preferenceCalls++;preferenceBody=body;return {id:'mock',init_point:'https://example.test/checkout'};}}};
const {normalizeItems}=require('../helpers/orderVariants'),{hashCartItems}=require('../helpers/mercadoPago'),{createPaidOrder}=require('../helpers/createPaidOrder');
async function main(){
 const items=[{product_id:1,cantidad:1,talla:'26',color:'Negro'},{product_id:1,cantidad:2,talla:'27',color:'Blanco'}];
 assert.equal(normalizeItems([...items,items[0]]).length,2);assert.equal(normalizeItems([...items,items[0]])[0].cantidad,2);
 assert.equal(hashCartItems(items),hashCartItems([...items].reverse()));assert.notEqual(hashCartItems(items),hashCartItems([{...items[0],color:'Blanco'},items[1]]));
 const legacy=[{product_id:1,cantidad:1}];assert.equal(hashCartItems(legacy),crypto.createHash('sha256').update(JSON.stringify(legacy)).digest('hex'));
 assert.throws(()=>normalizeItems([{...items[0],talla:'x'.repeat(81)}]));
 const app=express();app.use(express.json());app.use('/api/payments',require('../routes/public/payments.routes'));
 const server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
 try{
  const headers={'Content-Type':'application/json',Authorization:'Bearer '+jwt.sign({id:1,rol:'cliente'},process.env.JWT_SECRET)};
  const post=body=>fetch('http://127.0.0.1:'+server.address().port+'/api/payments/preference',{method:'POST',headers,body:JSON.stringify(body)});
  let res=await post({direccion_id:1,items});assert.equal(res.status,201);assert.equal(preferenceBody.items.length,2);assert.deepEqual(JSON.parse(preferenceBody.metadata.cart_items_json),items);
  assert.ok(preferenceBody.items[0].description.includes('Talla: 26'));
  columns=false;res=await post({direccion_id:1,items});assert.equal(res.status,503);assert.equal(preferenceCalls,1);columns=true;
  res=await post({direccion_id:1,items:[{...items[0],talla:'99'}]});assert.equal(res.status,400);
  stock=2;res=await post({direccion_id:1,items});assert.equal(res.status,409);stock=8;
  const payment={id:123,status:'approved',currency_id:'MXN',transaction_amount:1500,metadata:{user_id:'1',address_id:'1',cart_hash:hashCartItems(items)}};
  await createPaidOrder({payment,userId:1,addressId:1,items});assert.equal(saved.length,2);assert.deepEqual(saved.map(row=>row.slice(-2)),[['26','Negro'],['27','Blanco']]);assert.equal(decrements.reduce((sum,row)=>sum+row[0],0),3);
  await assert.rejects(()=>createPaidOrder({payment,userId:1,addressId:1,items:[{...items[0],color:'Blanco'},items[1]]}),/carrito no coincide/);
  console.log('VARIANTES OK: selección validada, variantes separadas, hash protegido, stock conjunto, migración faltante bloquea cobro y talla/color guardados. BD y pago simulados.');
 }finally{await new Promise(resolve=>server.close(resolve));}
}
main().catch(error=>{console.error(error);process.exitCode=1;});
