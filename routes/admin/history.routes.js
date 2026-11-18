const router=require('express').Router();
const {getDB}=require('../../config/db');
const {authMiddleware,adminOnly}=require('../../middlewares/auth');
const {auditEnabled}=require('../../helpers/audit');
router.use(authMiddleware,adminOnly);
router.get('/',async(req,res)=>{
 if(!auditEnabled())return res.status(503).json({error:'El historial está pendiente de activar después de crear su tabla.'});
 try{
  const conditions=[],params=[];
  if(req.query.entidad){if(!['inventario','pedidos','usuarios'].includes(req.query.entidad))return res.status(400).json({error:'Sección inválida.'});conditions.push('entidad=?');params.push(req.query.entidad);}
  const page=Number(req.query.pagina||1);if(!Number.isSafeInteger(page)||page<1||page>100000)return res.status(400).json({error:'Página inválida.'});
  const db=await getDB();const [rows]=await db.execute(`SELECT id,usuario_id,usuario,accion,entidad,entidad_id,antes,despues,creado_en FROM historial_admin ${conditions.length?'WHERE '+conditions.join(' AND '):''} ORDER BY id DESC LIMIT 51 OFFSET ${(page-1)*50}`,params);
  res.json({rows:rows.slice(0,50),hasMore:rows.length>50,page});
 }catch(error){console.error('Error consultando historial:',error.code||error.name);res.status(500).json({error:'No se pudo consultar el historial.'});}
});
module.exports=router;
