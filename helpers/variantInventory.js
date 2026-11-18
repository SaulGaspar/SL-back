const {auditedTransaction}=require('./audit');
const variantsEnabled=()=>process.env.SPORTLIKE_VARIANTS_ENABLED==='true';
function problem(message,statusCode=400){const error=new Error(message);error.statusCode=statusCode;throw error;}
function positive(value){const n=Number(value);if(!Number.isSafeInteger(n)||n<=0)problem('Identificador inválido.');return n;}
function nonnegative(value){if(!['number','string'].includes(typeof value)||String(value).trim()==='')problem('Indica una cantidad.');const n=Number(value);if(!Number.isSafeInteger(n)||n<0||n>2147483647)problem('Las existencias deben ser enteros entre 0 y 2147483647.');return n;}
const list=value=>String(value||'').split(',').map(v=>v.trim()).filter(Boolean);
const option=value=>String(value||'').trim()||'Único';
function requireVariants(){if(!variantsEnabled())problem('El inventario por talla/color está pendiente de activar después de la migración.',503);}
async function variantAvailability(db,productId){
 if(!variantsEnabled())return null;
 const [rows]=await db.execute(`SELECT v.talla, v.color, MAX(v.stock) AS stock
 FROM inventario_variantes v JOIN inventory i ON i.id=v.inventario_id
 JOIN branches b ON b.id=i.branch_id AND b.activo=1
 WHERE i.product_id=? GROUP BY v.talla,v.color`,[productId]);return rows;
}
async function allocateVariant(conn,item){
 const [rows]=await conn.execute(`SELECT i.id AS inventory_id, v.id AS variant_id, i.branch_id, b.nombre, v.stock, p.precio
 FROM inventario_variantes v JOIN inventory i ON i.id=v.inventario_id
 JOIN branches b ON b.id=i.branch_id AND b.activo=1 JOIN products p ON p.id=i.product_id AND p.activo=1
 WHERE i.product_id=? AND v.talla=? AND v.color=? AND v.stock>=?
 ORDER BY i.branch_id LIMIT 1 FOR UPDATE`,[item.product_id,option(item.talla),option(item.color),item.cantidad]);
 if(!rows.length)problem('La talla y el color seleccionados no están disponibles. Revisa tu carrito.',409);
 return rows[0];
}
async function deductVariant(conn,item){
 const [result]=await conn.execute('UPDATE inventario_variantes SET stock=stock-? WHERE id=? AND stock>=?',[item.cantidad,item.variant_id,item.cantidad]);
 if(result.affectedRows!==1)problem('La disponibilidad cambió. Revisa el pedido.',409);
}
async function restoreVariant(conn,inventoryId,item){
 const [variants]=await conn.execute('SELECT id FROM inventario_variantes WHERE inventario_id=? AND talla=? AND color=? FOR UPDATE',[inventoryId,option(item.talla),option(item.color)]);
 if(!variants.length)problem('No se puede devolver inventario sin identificar la talla y el color del pedido. Revisa el pedido histórico.',409);
 await conn.execute('UPDATE inventario_variantes SET stock=stock+? WHERE id=?',[item.cantidad,variants[0].id]);
}
async function saveVariants(db,id,raw,actor){
 requireVariants();id=positive(id);
 if(!Array.isArray(raw)||!raw.length||raw.length>200)problem('Agrega entre 1 y 200 combinaciones.');
 return auditedTransaction(db,{actor,action:'configurar_variantes',entity:'inventario',id},async conn=>{
  const [[inventory]]=await conn.execute('SELECT i.*, p.talla, p.colores FROM inventory i JOIN products p ON p.id=i.product_id WHERE i.id=? FOR UPDATE',[id]);
  if(!inventory)problem('Inventario no encontrado.',404);
  const [before]=await conn.execute('SELECT id,talla,color,stock FROM inventario_variantes WHERE inventario_id=? ORDER BY id FOR UPDATE',[id]);
  const sizes=list(inventory.talla),colors=list(inventory.colores),keys=new Set();
  const rows=raw.map(row=>{
   if(!row||typeof row!=='object'||Array.isArray(row))problem('Combinación inválida.');
   const talla=option(row.talla),color=option(row.color),stock=nonnegative(row.stock),key=JSON.stringify([talla.toLowerCase(),color.toLowerCase()]);
   if(talla.length>80||color.length>80||keys.has(key))problem('Hay combinaciones inválidas o repetidas.');keys.add(key);
   if(!(sizes.length?sizes:['Único']).includes(talla)||!(colors.length?colors:['Único']).includes(color)){
    if(stock!==0||!before.some(v=>v.talla===talla&&v.color===color))problem('La talla o el color no pertenece al producto.');
   }
   return {talla,color,stock};
  });
  if(before.some(old=>!rows.some(row=>row.talla===old.talla&&row.color===old.color)))problem('Conserva las combinaciones existentes. Para retirarlas, deja su stock en cero.');
  const total=rows.reduce((sum,row)=>sum+row.stock,0);nonnegative(total);
  if(!before.length&&total!==Number(inventory.stock))problem(`El primer desglose debe sumar las ${inventory.stock} unidades existentes; no se repartirán automáticamente.`,409);
  for(const row of rows)await conn.execute('INSERT INTO inventario_variantes (inventario_id,talla,color,stock) VALUES (?,?,?,?) ON DUPLICATE KEY UPDATE stock=VALUES(stock)',[id,row.talla,row.color,row.stock]);
  await conn.execute('UPDATE inventory SET stock=? WHERE id=?',[total,id]);
  return {before:{total:inventory.stock,variantes:before},after:{total,variantes:rows},result:{message:'Existencias por talla y color guardadas.',stock:total}};
 });
}
module.exports={variantsEnabled,requireVariants,variantAvailability,allocateVariant,deductVariant,restoreVariant,saveVariants,positive,nonnegative,problem,option};
