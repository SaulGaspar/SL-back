// Prueba aislada: usa la ruta real con un adaptador de BD en memoria, sin tocar MySQL.
const assert=require('node:assert/strict');
const express=require('express');
const jwt=require('jsonwebtoken');
process.env.JWT_SECRET='sportlike-isolated-profile-check-secret';
let user={id:1,nombre:'Ana',apellidoP:'Prueba',apellidoM:'',usuario:'ana_test',correo:'ana@example.test',telefono:'7711234567',rol:'cliente'};
const db={execute:async(sql,params)=>{
  if(sql.startsWith('UPDATE users SET nombre')){[user.nombre,user.apellidoP,user.apellidoM,user.telefono,user.usuario]=params;return [{affectedRows:1}];}
  if(sql.includes('(usuario = ? OR telefono = ?)'))return [[]];
  if(sql.startsWith('SELECT id, nombre')){assert.ok(sql.includes('telefono'));return [params[0]===1?[{...user}]:[]];}
  throw new Error('SQL inesperado en prueba: '+sql);
}};
const dbPath=require.resolve('../config/db');
require.cache[dbPath]={id:dbPath,filename:dbPath,loaded:true,exports:{getDB:async()=>db}};
const router=require('../routes/public/profile.routes');
async function main(){
  const app=express();app.use(express.json());app.use('/api',router);
  const server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
  const base='http://127.0.0.1:'+server.address().port;
  const headers={Authorization:'Bearer '+jwt.sign({id:1,rol:'cliente'},process.env.JWT_SECRET),'Content-Type':'application/json'};
  try{
    assert.equal((await fetch(base+'/api/me')).status,401);
    assert.equal((await (await fetch(base+'/api/me',{headers})).json()).telefono,'7711234567');
    assert.equal((await fetch(base+'/api/update-profile',{method:'POST',headers,body:JSON.stringify({...user,telefono:'123'})})).status,400);
    const saved=await (await fetch(base+'/api/update-profile',{method:'POST',headers,body:JSON.stringify({...user,nombre:' Ana ',telefono:'7717654321'})})).json();
    assert.equal(saved.user.nombre,'Ana');assert.equal(saved.user.telefono,'7717654321');
    assert.equal((await (await fetch(base+'/api/me',{headers})).json()).telefono,'7717654321');
    console.log('PERFIL BACKEND OK: autenticación, teléfono al consultar/editar/recargar, validación y respuesta normalizada. Sin acceso a la BD real.');
  }finally{await new Promise(resolve=>server.close(resolve));}
}
main().catch(error=>{console.error(error);process.exitCode=1;});
