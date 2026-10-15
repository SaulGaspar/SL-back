const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const SIGNUP_AUDIENCE = 'sportlike-google-registration';
const STATE_AUDIENCE = 'sportlike-google-state';
const STATE_COOKIE = 'sl_google_state';
const secret = () => process.env.JWT_SECRET;

function googleSession(user) {
  if (user.lockedUntil && new Date(user.lockedUntil) > new Date()) throw new Error('La cuenta está bloqueada temporalmente.');
  // Se conserva la política existente: Google no concede acceso administrativo.
  const rol = user.rol === 'admin' ? 'cliente' : user.rol;
  const sessionUser = {id:user.id,nombre:user.nombre,apellidoP:user.apellidoP,apellidoM:user.apellidoM,usuario:user.usuario,correo:user.correo,telefono:user.telefono ?? null,rol};
  const token = jwt.sign({...sessionUser,proveedor:'google'},secret(),{expiresIn:'7d',algorithm:'HS256'});
  return {token,user:sessionUser};
}

function googleRegistration(profile, correo) {
  const parts = String(profile.displayName || '').trim().split(/\s+/);
  return jwt.sign({purpose:'google-registration',correo,nombre:String(profile.name?.givenName || parts.shift() || '').slice(0,100),apellidoP:String(profile.name?.familyName || parts.join(' ') || '').slice(0,100),apellidoM:''},secret(),{audience:SIGNUP_AUDIENCE,expiresIn:'10m',jwtid:crypto.randomUUID(),algorithm:'HS256'});
}

function readRegistration(req) {
  const token = req.headers.authorization?.match(/^Bearer (\S+)$/)?.[1];
  const data = jwt.verify(token || '',secret(),{audience:SIGNUP_AUDIENCE,algorithms:['HS256']});
  if (data.purpose !== 'google-registration' || typeof data.correo !== 'string') throw new Error('Registro inválido');
  return data;
}

function frontendOrigin(requested) {
  const base = new URL(process.env.CLIENT_URL || 'https://sportlikeapps.netlify.app').origin;
  const allowed = new Set([base,'http://localhost:1234']);
  if (process.env.FRONTEND_URL) allowed.add(new URL(process.env.FRONTEND_URL).origin);
  if (!requested) return base;
  const candidate = new URL(requested);
  if (!allowed.has(candidate.origin) || candidate.username || candidate.password || candidate.pathname !== '/' || candidate.search || candidate.hash) throw new Error('Origen de regreso no permitido');
  return candidate.origin;
}

function beginGoogle(req,res) {
  const origin = frontendOrigin(req.query.return_to);
  const nonce = crypto.randomBytes(24).toString('base64url');
  res.cookie(STATE_COOKIE,nonce,{httpOnly:true,secure:req.secure,sameSite:'lax',maxAge:10*60*1000,path:'/'});
  return jwt.sign({origin,nonce},secret(),{audience:STATE_AUDIENCE,expiresIn:'10m',algorithm:'HS256'});
}

function finishGoogleState(req,res) {
  const data = jwt.verify(req.query.state || '',secret(),{audience:STATE_AUDIENCE,algorithms:['HS256']});
  const nonce = (req.headers.cookie || '').split(';').map(item=>item.trim()).find(item=>item.startsWith(STATE_COOKIE+'='))?.slice(STATE_COOKIE.length+1);
  if (!nonce || typeof data.nonce !== 'string' || nonce.length !== data.nonce.length || !crypto.timingSafeEqual(Buffer.from(nonce),Buffer.from(data.nonce))) throw new Error('La solicitud de acceso expiró');
  res.clearCookie(STATE_COOKIE,{httpOnly:true,secure:req.secure,sameSite:'lax',path:'/'});
  return frontendOrigin(data.origin);
}

module.exports = {googleSession,googleRegistration,readRegistration,beginGoogle,finishGoogleState};
