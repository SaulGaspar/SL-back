const auditEnabled=()=>process.env.SPORTLIKE_AUDIT_ENABLED==='true';
async function writeAudit(conn,{actor,action,entity,id,before=null,after=null}){
 if(!auditEnabled())return;
 await conn.execute('INSERT INTO historial_admin (usuario_id, usuario, accion, entidad, entidad_id, antes, despues) VALUES (?, ?, ?, ?, ?, ?, ?)',[
  actor?.id||null,String(actor?.usuario|| (actor?.id?`Usuario #${actor.id}`:'Sistema')).slice(0,80),action,entity,id||null,
  before==null?null:JSON.stringify(before),after==null?null:JSON.stringify(after)
 ]);
}
async function auditedTransaction(db,context,operation){
 const conn=await db.getConnection();let started=false;
 try{await conn.beginTransaction();started=true;const change=await operation(conn);await writeAudit(conn,{...context,...change});await conn.commit();started=false;return change.result;}
 catch(error){if(started)await conn.rollback();throw error;}finally{conn.release();}
}
module.exports={auditEnabled,writeAudit,auditedTransaction};
