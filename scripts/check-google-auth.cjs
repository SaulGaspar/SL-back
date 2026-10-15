// Google, BD y respuestas sustituidos: sin credenciales de Google ni registros reales.
const assert=require('node:assert/strict'),express=require('express'),jwt=require('jsonwebtoken'),passport=require('passport');
process.env.JWT_SECRET='isolated-google-check-secret';process.env.GOOGLE_CLIENT_ID='isolated-google-client';process.env.GOOGLE_CLIENT_SECRET='isolated-google-secret';process.env.GOOGLE_CALLBACK_URL='http://localhost/auth/google/callback';process.env.CLIENT_URL='https://sportlikeapps.netlify.app';
let users=[{id:1,nombre:'Nombre guardado',apellidoP:'Apellido guardado',apellidoM:'Segundo',correo:'ana@example.test',usuario:'mi_usuario',telefono:'7711234567',rol:'cliente',password:'hash-existente',verificado:1}];let inserts=0;
const db={execute:async(sql,params)=>{
 if(sql==='SELECT * FROM users WHERE correo = ?')return [users.filter(user=>user.correo===params[0]).map(user=>({...user}))];
 if(sql==='SELECT id FROM users WHERE usuario = ?')return [users.filter(user=>user.usuario===params[0]).map(user=>({id:user.id}))];
 if(sql==='SELECT * FROM users WHERE id = ?')return [users.filter(user=>user.id===params[0])];
 if(sql.startsWith('SELECT id, nombre'))return [users.filter(user=>user.id===params[0]).map(user=>({...user}))];
 if(sql.startsWith('INSERT INTO users')){inserts++;const [nombre,apellidoP,apellidoM,correo,usuario,password,rol]=params;const user={id:users.length+1,nombre,apellidoP,apellidoM,correo,usuario,password,rol,verificado:1};users.push(user);return [{insertId:user.id}];}
 throw new Error('Consulta inesperada en Google: '+sql);
}};
const dbPath=require.resolve('../config/db');require.cache[dbPath]={id:dbPath,filename:dbPath,loaded:true,exports:{getDB:async()=>db}};
const router=require('../routes/public/auth.routes');
const {finishGoogleState,googleRegistration}=require('../helpers/googleAuth');
const verify=profile=>new Promise((resolve,reject)=>passport._strategy('google')._verify('unused','unused',profile,(error,result)=>error?reject(error):resolve(result)));
async function main(){
 const app=express();app.use(express.json());app.use('/auth',router);app.use('/api',router);app.use('/api',require('../routes/public/profile.routes'));
 const server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));const base='http://127.0.0.1:'+server.address().port;
 const googleProfile={displayName:'Nombre de Google',emails:[{value:'ANA@EXAMPLE.TEST',verified:true}],name:{givenName:'Nombre Google',familyName:'Apellido Google'}};
 try{
  const result=await verify(googleProfile);assert.ok(result.token);assert.equal(result.user.usuario,'mi_usuario');assert.equal(result.user.nombre,'Nombre guardado');assert.equal(result.user.telefono,'7711234567');assert.equal(users[0].password,'hash-existente');assert.equal(inserts,0);
  const existing=await (await fetch(base+'/api/me',{headers:{Authorization:'Bearer '+result.token}})).json();assert.equal(existing.usuario,'mi_usuario');assert.equal(existing.correo,'ana@example.test');
  const pending=await verify({...googleProfile,emails:[{value:'nuevo@example.test',verified:true}]});assert.ok(pending.registration_token);assert.equal(pending.token,undefined);assert.equal(inserts,0);
  const claims=jwt.decode(pending.registration_token);assert.equal(claims.id,undefined);assert.equal(claims.rol,undefined);
  const headers={'Content-Type':'application/json',Authorization:'Bearer '+pending.registration_token};
  assert.equal((await fetch(base+'/api/me',{headers})).status,401);
  const preview=await (await fetch(base+'/api/google/registration',{headers})).json();assert.equal(preview.correo,'nuevo@example.test');
  const complete=body=>fetch(base+'/api/google/complete',{method:'POST',headers,body:JSON.stringify(body)});
  assert.equal((await complete({usuario:'a'})).status,400);assert.equal((await complete({usuario:'mi_usuario'})).status,409);assert.equal(inserts,0);
  const created=await complete({usuario:'deportista_nuevo',correo:'otro@example.test',rol:'admin'});assert.equal(created.status,201);const session=await created.json();assert.equal(session.user.correo,'nuevo@example.test');assert.equal(session.user.usuario,'deportista_nuevo');assert.equal(session.user.rol,'cliente');assert.equal(inserts,1);assert.notEqual(users[1].password,'hash-existente');
  assert.equal((await complete({usuario:'otro_usuario'})).status,200);assert.equal(inserts,1);assert.equal(users[1].usuario,'deportista_nuevo');
  const invalidHeaders={...headers,Authorization:'Bearer '+result.token};assert.equal((await fetch(base+'/api/google/complete',{method:'POST',headers:invalidHeaders,body:'{"usuario":"prueba"}'})).status,401);
  const expired=jwt.sign({purpose:'google-registration',correo:'x@example.test'},process.env.JWT_SECRET,{audience:'sportlike-google-registration',expiresIn:-1});assert.equal((await fetch(base+'/api/google/registration',{headers:{Authorization:'Bearer '+expired}})).status,401);
  assert.equal(await verify({...googleProfile,emails:[{value:'ana@example.test',verified:false}]}),false);
  const start=await fetch(base+'/auth/google?return_to='+encodeURIComponent('http://localhost:1234'),{redirect:'manual'});assert.equal(start.status,302);const oauth=new URL(start.headers.get('location'));const state=oauth.searchParams.get('state');const cookie=start.headers.get('set-cookie').split(';')[0];const origin=finishGoogleState({query:{state},headers:{cookie},secure:false},{clearCookie:()=>{}});assert.equal(origin,'http://localhost:1234');assert.throws(()=>finishGoogleState({query:{state},headers:{cookie:''}},{clearCookie:()=>{}}));
  assert.equal((await fetch(base+'/auth/google?return_to=https://no-permitido.example',{redirect:'manual'})).status,400);
  console.log('GOOGLE OK: cuenta existente intacta, usuario nuevo a elección, ticket temporal sin acceso privado, colisiones, reintentos sin duplicados y regreso seguro al origen. Sin Google ni BD reales.');
 }finally{await new Promise(resolve=>server.close(resolve));}
}
main().catch(error=>{console.error(error);process.exitCode=1;});
