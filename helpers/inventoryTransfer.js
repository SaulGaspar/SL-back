const {writeAudit}=require('./audit');
const {variantsEnabled,option}=require('./variantInventory');
function problem(message,statusCode=400){const error=new Error(message);error.statusCode=statusCode;throw error;}
async function transferInventory(db,input,actor){
  const productId=Number(input.product_id),from=Number(input.from_branch_id),to=Number(input.to_branch_id),quantity=Number(input.cantidad);
  if(![productId,from,to,quantity].every(value=>Number.isSafeInteger(value)&&value>0))problem('Producto, sucursales y cantidad deben ser enteros positivos.');
  if(from===to)problem('No se puede transferir a la misma sucursal.');
  const conn=await db.getConnection();let transaction=false;
  try{
    await conn.beginTransaction();transaction=true;
    // Orden fijo de bloqueos, incluso para transferencias en direcciones opuestas.
    const [branches]=await conn.execute('SELECT id, activo FROM branches WHERE id IN (?, ?) ORDER BY id FOR UPDATE',[Math.min(from,to),Math.max(from,to)]);
    if(branches.length!==2||branches.some(branch=>Number(branch.activo)!==1))problem('Selecciona dos sucursales activas.');
    const [[product]]=await conn.execute('SELECT id, activo FROM products WHERE id = ? FOR UPDATE',[productId]);
    if(!product||Number(product.activo)!==1)problem('El producto no está disponible.',404);
    const [inventory]=await conn.execute('SELECT id, branch_id, stock FROM inventory WHERE product_id = ? AND branch_id IN (?, ?) ORDER BY branch_id FOR UPDATE',[productId,Math.min(from,to),Math.max(from,to)]);
    const source=inventory.find(row=>Number(row.branch_id)===from),destination=inventory.find(row=>Number(row.branch_id)===to);
    if(!source||Number(source.stock)<quantity)problem('La sucursal origen no tiene existencias suficientes.',409);
    let selectedVariant;
    if(variantsEnabled()){
      const [variants]=await conn.execute('SELECT id,inventario_id,talla,color,stock FROM inventario_variantes WHERE inventario_id IN (?,?) ORDER BY inventario_id,id FOR UPDATE',[source.id,destination?.id||0]);
      selectedVariant=variants.find(v=>Number(v.inventario_id)===Number(source.id)&&v.talla===option(input.talla)&&v.color===option(input.color));
      if(!selectedVariant||Number(selectedVariant.stock)<quantity)problem('Configura y selecciona una talla/color con existencias suficientes.',409);
      if(destination&&Number(destination.stock)>0&&!variants.some(v=>Number(v.inventario_id)===Number(destination.id)))problem('Desglosa primero el inventario existente de la sucursal destino.',409);
      const [changed]=await conn.execute('UPDATE inventario_variantes SET stock=stock-? WHERE id=? AND stock>=?',[quantity,selectedVariant.id,quantity]);if(changed.affectedRows!==1)problem('La disponibilidad cambió.',409);
    }
    const [updated]=await conn.execute('UPDATE inventory SET stock = stock - ? WHERE id = ? AND stock >= ?',[quantity,source.id,quantity]);
    if(updated.affectedRows!==1)problem('El inventario cambió. Actualiza e intenta nuevamente.',409);
    let destinationId=destination?.id;
    if(destination)await conn.execute('UPDATE inventory SET stock = stock + ? WHERE id = ?',[quantity,destination.id]);
    else {const [inserted]=await conn.execute('INSERT INTO inventory (product_id, branch_id, stock, min_stock) VALUES (?, ?, ?, 10)',[productId,to,quantity]);destinationId=inserted.insertId;}
    if(selectedVariant)await conn.execute('INSERT INTO inventario_variantes (inventario_id,talla,color,stock) VALUES (?,?,?,?) ON DUPLICATE KEY UPDATE stock=stock+VALUES(stock)',[destinationId,selectedVariant.talla,selectedVariant.color,quantity]);
    await writeAudit(conn,{actor,action:'transferir',entity:'inventario',id:source.id,before:{product_id:productId,origen:from,destino:to,stock_origen:Number(source.stock),stock_destino:Number(destination?.stock||0)},after:{cantidad:quantity,talla:selectedVariant?.talla||null,color:selectedVariant?.color||null,stock_origen:Number(source.stock)-quantity,stock_destino:Number(destination?.stock||0)+quantity}});
    await conn.commit();transaction=false;
    return {message:'Transferencia completada exitosamente'};
  }catch(error){if(transaction)await conn.rollback();throw error;}finally{conn.release();}
}
module.exports={transferInventory};
