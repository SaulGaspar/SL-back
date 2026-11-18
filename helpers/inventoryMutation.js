const {auditedTransaction,writeAudit}=require('./audit');
const {variantsEnabled,positive,nonnegative,problem}=require('./variantInventory');
async function mutateInventory(db,{id,input={},action,actor}){
 id=id==null?null:positive(id);
 const stock=action==='eliminar'?null:nonnegative(input.stock);
 return auditedTransaction(db,{actor,action:`inventario_${action}`,entity:'inventario',id},async conn=>{
  let current=null;
  if(id){const [[row]]=await conn.execute('SELECT * FROM inventory WHERE id=? FOR UPDATE',[id]);if(!row)problem('Inventario no encontrado.',404);current=row;}
  const minimum=action==='eliminar'?null:nonnegative(input.min_stock ?? current?.min_stock ?? 10);
  if(current&&variantsEnabled()){
   const [variants]=await conn.execute('SELECT id FROM inventario_variantes WHERE inventario_id=? FOR UPDATE',[id]);
   if(variants.length&&(action==='eliminar'||stock!==Number(current.stock)))problem('Este inventario se administra por talla/color. Ajusta sus variantes, no el total general.',409);
  }
  let result;
  if(action==='crear'){
   const productId=positive(input.product_id),branchId=positive(input.branch_id);
   const [[product]]=await conn.execute('SELECT id,activo FROM products WHERE id=? FOR UPDATE',[productId]);
   const [[branch]]=await conn.execute('SELECT id,activo FROM branches WHERE id=?',[branchId]);
   if(!product||Number(product.activo)!==1||!branch||Number(branch.activo)!==1)problem('Selecciona un producto y una sucursal activos.');
   const [existing]=await conn.execute('SELECT id FROM inventory WHERE product_id=? AND branch_id=?',[productId,branchId]);if(existing.length)problem('Este producto ya tiene inventario en esa sucursal.',409);
   [result]=await conn.execute('INSERT INTO inventory (product_id,branch_id,stock,min_stock) VALUES (?,?,?,?)',[productId,branchId,stock,minimum]);id=result.insertId;
   return {id,before:null,after:{product_id:productId,branch_id:branchId,stock,min_stock:minimum},result:{id,message:'Inventario creado.'}};
  }
  if(action==='eliminar'){await conn.execute('DELETE FROM inventory WHERE id=?',[id]);return {before:current,after:null,result:{message:'Inventario eliminado.'}};}
  await conn.execute('UPDATE inventory SET stock=?,min_stock=? WHERE id=?',[stock,minimum,id]);
  return {before:current,after:{...current,stock,min_stock:minimum},result:{message:'Inventario actualizado.'}};
 });
}
async function saveProductInventory(conn,productId,rows,actor){
 if(!Array.isArray(rows)||rows.length>500)problem('Inventario inválido.');
 const seen=new Set();
 for(const input of rows){
  const branch=positive(input.branch_id),stock=nonnegative(input.stock),minimum=nonnegative(input.min_stock??10);
  if(seen.has(branch))problem('Hay sucursales repetidas.');seen.add(branch);
  const [[active]]=await conn.execute('SELECT id FROM branches WHERE id=? AND activo=1',[branch]);if(!active)problem('Sucursal no disponible.');
  const [[before]]=await conn.execute('SELECT * FROM inventory WHERE product_id=? AND branch_id=? FOR UPDATE',[productId,branch]);
  if(before&&variantsEnabled()){
   const [variants]=await conn.execute('SELECT id FROM inventario_variantes WHERE inventario_id=? FOR UPDATE',[before.id]);
   if(variants.length&&stock!==Number(before.stock))problem('Ajusta las existencias desde Inventario → Talla y color.',409);
  }
  const [result]=await conn.execute('INSERT INTO inventory (product_id,branch_id,stock,min_stock) VALUES (?,?,?,?) ON DUPLICATE KEY UPDATE stock=VALUES(stock),min_stock=VALUES(min_stock)',[productId,branch,stock,minimum]);
  await writeAudit(conn,{actor,action:before?'inventario_actualizar':'inventario_crear',entity:'inventario',id:before?.id||result.insertId,before:before||null,after:{product_id:productId,branch_id:branch,stock,min_stock:minimum}});
 }
}
module.exports={mutateInventory,saveProductInventory};
