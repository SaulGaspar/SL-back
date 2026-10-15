// Rutas reales con BD y correo sustituidos: no consulta ni modifica datos reales.
const assert = require('node:assert/strict');
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
process.env.JWT_SECRET = 'isolated-login-check-secret';
process.env.GOOGLE_CLIENT_ID = 'isolated-client';
process.env.GOOGLE_CLIENT_SECRET = 'isolated-secret';
process.env.GOOGLE_CALLBACK_URL = 'http://localhost/auth/google/callback';
let user, databaseCalls = 0;
const db = { execute: async (sql, params) => {
  databaseCalls++;
  if (sql.startsWith('SELECT id, nombre')) {
    assert.ok(sql.includes('WHERE correo = ?'));
    return [params[0] === user.correo ? [{...user}] : []];
  }
  if (sql.startsWith('UPDATE users SET failedAttempts=0')) { user.failedAttempts = 0; user.lockedUntil = null; return [{affectedRows:1}]; }
  if (sql.startsWith('UPDATE users SET failedAttempts=?')) { [user.failedAttempts,user.lockedUntil] = params; return [{affectedRows:1}]; }
  throw new Error('Consulta no esperada: ' + sql);
}};
const dbPath = require.resolve('../config/db');
require.cache[dbPath] = { id:dbPath, filename:dbPath, loaded:true, exports:{getDB:async()=>db} };
const mailPath = require.resolve('../helpers/mailer');
require.cache[mailPath] = { id:mailPath, filename:mailPath, loaded:true, exports:{createTransporter:()=>{throw new Error('No se deben enviar correos');}} };
async function main() {
  user = {id:1,correo:'ana@example.test',usuario:'ana_test',nombre:'Ana',rol:'cliente',verificado:1,failedAttempts:0,lockedUntil:null,password:await bcrypt.hash('Prueba123!',4)};
  const app = express(); app.use(express.json());
  app.use('/api',require('../routes/public/auth.routes'));
  app.use('/api/promotions',require('../routes/public/promotions.routes'));
  app.use('/api/admin/promotions',require('../routes/admin/promotions.routes'));
  const server = app.listen(0,'127.0.0.1'); await new Promise(resolve=>server.once('listening',resolve));
  const base = 'http://127.0.0.1:'+server.address().port;
  const login = body => fetch(base+'/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  try {
    for (const body of [{usuario:'ana_test',password:'Prueba123!'},{correo:{},password:'x'},{correo:'no-es-correo',password:'x'},{correo:'ana@example.test',password:[]}]) assert.equal((await login(body)).status,400);
    assert.equal(databaseCalls,0);
    assert.equal((await login({correo:'desconocido@example.test',password:'Prueba123!'})).status,401);
    const response = await login({correo:' ANA@EXAMPLE.TEST ',password:'Prueba123!'});
    assert.equal(response.status,200);
    const payload = await response.json(); assert.equal(payload.user.correo,user.correo); assert.equal(payload.user.password,undefined);
    assert.equal(jwt.verify(payload.token,process.env.JWT_SECRET).id,1);
    user.verificado = 0; assert.equal((await login({correo:user.correo,password:'Prueba123!'})).status,403); user.verificado=1;
    user.failedAttempts='1'; assert.equal((await login({correo:user.correo,password:'incorrecta'})).status,401); assert.equal(user.failedAttempts,2);
    assert.equal((await login({correo:user.correo,password:'incorrecta'})).status,403); assert.equal(user.failedAttempts,3);
    assert.equal((await login({correo:user.correo,password:'Prueba123!'})).status,403);
    const before = databaseCalls;
    assert.deepEqual(await (await fetch(base+'/api/promotions/active')).json(),[]);
    assert.equal((await fetch(base+'/api/admin/promotions')).status,401);
    const headers = {'Content-Type':'application/json',Authorization:'Bearer '+jwt.sign({id:1,rol:'admin'},process.env.JWT_SECRET)};
    for (const [method,route] of [['GET',''],['POST',''],['PUT','/1'],['PATCH','/1/status'],['POST','/1/notify'],['DELETE','/1']]) {
      const result = await fetch(base+'/api/admin/promotions'+route,{method,headers,...(['POST','PUT','PATCH'].includes(method)?{body:'{}'}:{})});
      assert.equal(result.status,503); assert.equal((await result.json()).code,'PROMOTIONS_PAUSED');
    }
    assert.equal(databaseCalls,before);
    console.log('LOGIN Y PROMOCIONES OK: acceso por correo, validación, JWT, verificación, bloqueo y promociones pausadas sin BD ni correos reales.');
  } finally { await new Promise(resolve=>server.close(resolve)); }
}
main().catch(error=>{console.error(error);process.exitCode=1;});
