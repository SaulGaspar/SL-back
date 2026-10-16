function invalid(message) {const error=new Error(message);error.statusCode=400;throw error;}
function normalizeItems(raw) {
  if(!Array.isArray(raw)||!raw.length||raw.length>50)invalid('El carrito no contiene productos válidos');
  const merged=new Map();
  for(const item of raw){
    const product_id=Number(item.product_id),cantidad=Number(item.cantidad);
    if(!Number.isSafeInteger(product_id)||product_id<=0)invalid('Hay un producto inválido en el carrito');
    if(!Number.isSafeInteger(cantidad)||cantidad<=0||cantidad>20)invalid('La cantidad solicitada no es válida');
    const variant={};
    for(const field of ['talla','color']){
      if(item[field]!=null){
        if(typeof item[field]!=='string'||!item[field].trim()||item[field].trim().length>80)invalid(`La selección de ${field} no es válida`);
        variant[field]=item[field].trim();
      }
    }
    const key=JSON.stringify([product_id,variant.talla||'',variant.color||'']);
    const previous=merged.get(key);const total=cantidad+(previous?.cantidad||0);
    if(total>20)invalid('La cantidad solicitada no es válida');
    merged.set(key,{product_id,cantidad:total,...variant});
  }
  return [...merged.values()].sort((a,b)=>a.product_id-b.product_id || (a.talla||'').localeCompare(b.talla||'') || (a.color||'').localeCompare(b.color||''));
}
async function requireVariantColumns(db) {
  const [columns]=await db.execute('SHOW COLUMNS FROM order_items');
  if(!['talla','color'].every(field=>columns.some(column=>column.Field===field))){
    const error=new Error('El pago está temporalmente deshabilitado mientras se actualizan las opciones de los productos.');error.statusCode=503;throw error;
  }
}
function validateSelection(item,product){
  for(const [field,source] of [['talla','talla'],['color','colores']]){
    const options=String(product[source]||'').split(',').map(value=>value.trim()).filter(Boolean);
    if(options.length ? !options.includes(item[field]) : item[field] && item[field]!=='Único')invalid(`Revisa la selección de ${field} para "${product.nombre}".`);
  }
}
module.exports={normalizeItems,requireVariantColumns,validateSelection};
