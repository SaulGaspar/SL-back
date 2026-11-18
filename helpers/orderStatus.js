const {normalizeOrderStatus}=require('./orderStats');
const {writeAudit}=require('./audit');
const {variantsEnabled,restoreVariant}=require('./variantInventory');
const {sendOrderStatusNotification}=require('./pushNotifications');
const transitions={pendiente:['preparando','cancelado'],preparando:['en_camino','cancelado'],en_camino:['entregado'],entregado:[],cancelado:[]};
const allowedOrderStatuses=status=>transitions[normalizeOrderStatus(status)]||[];
function problem(message,statusCode=409){const error=new Error(message);error.statusCode=statusCode;throw error;}
async function changeOrderStatus(db,id,status,confirmCancellation,actor){
  id=Number(id);
  if(!Number.isSafeInteger(id)||id<=0||!Object.hasOwn(transitions,status))problem('Pedido o estado inválido.',400);
  const conn=await db.getConnection();let transaction=false;
  try{
    await conn.beginTransaction();transaction=true;
    const [[order]]=await conn.execute('SELECT id, user_id, status, sucursal, pedido_ref FROM orders WHERE id = ? FOR UPDATE',[id]);
    if(!order)problem('Orden no encontrada.',404);
    const previous=normalizeOrderStatus(order.status);
    if(previous===status){await conn.commit();transaction=false;return {message:'El pedido ya tiene ese estado.',status,alreadyProcessed:true,allowed_statuses:allowedOrderStatuses(status)};}
    if(!allowedOrderStatuses(previous).includes(status))problem(`No se puede cambiar un pedido ${previous} a ${status}. Actualiza la lista.`);
    if(status==='cancelado'){
      if(confirmCancellation!==true)problem('Confirma la cancelación: se devolverá inventario, pero no se realizará ningún reembolso automático.',400);
      const [items]=await conn.execute('SELECT product_id,talla,color,SUM(cantidad) AS cantidad FROM order_items WHERE order_id = ? GROUP BY product_id,talla,color ORDER BY product_id,talla,color',[id]);
      if(!items.length)problem('El pedido no tiene detalle suficiente para devolver inventario. Revisa el pedido antes de cancelarlo.');
      for(const item of items){
        const quantity=Number(item.cantidad);
        if(!Number.isSafeInteger(quantity)||quantity<=0)problem('El pedido contiene cantidades inválidas.');
        if(variantsEnabled()){
          const [[inventory]]=await conn.execute('SELECT id FROM inventory WHERE product_id=? AND branch_id=? FOR UPDATE',[item.product_id,order.sucursal]);
          if(!inventory)problem('Falta el inventario original; revisa la cancelación.');
          await restoreVariant(conn,inventory.id,item);
        }
        await conn.execute('INSERT INTO inventory (product_id, branch_id, stock, min_stock) VALUES (?, ?, ?, 10) ON DUPLICATE KEY UPDATE stock = stock + VALUES(stock)',[item.product_id,order.sucursal,quantity]);
        await writeAudit(conn,{actor,action:'entrada_por_cancelacion',entity:'inventario',before:{product_id:item.product_id,sucursal:order.sucursal,talla:item.talla||null,color:item.color||null},after:{pedido_id:id,movimiento:quantity}});
      }
    }
    await conn.execute('UPDATE orders SET status = ? WHERE id = ?',[status,id]);
    await writeAudit(conn,{actor,action:'cambiar_estado',entity:'pedidos',id,before:{status:previous},after:{status,inventario_restituido:status==='cancelado',sucursal:order.sucursal}});
    await conn.commit();transaction=false;
    await sendOrderStatusNotification(db,{userId:order.user_id,orderId:order.id,pedidoRef:order.pedido_ref,status}).catch(error=>console.warn('No se pudo enviar la notificación del pedido:',error.message));
    return {message:status==='cancelado'?'Pedido cancelado e inventario restituido. Revisa por separado cualquier reembolso en Mercado Pago.':'Estado actualizado correctamente',status,inventoryRestored:status==='cancelado',allowed_statuses:allowedOrderStatuses(status)};
  }catch(error){if(transaction)await conn.rollback();throw error;}finally{conn.release();}
}
module.exports={allowedOrderStatuses,changeOrderStatus};
