const jwt = require('jsonwebtoken');
const {getDB}=require('../config/db');

const JWT_SECRET = process.env.JWT_SECRET;

// ================================
// 🔐 AUTHENTICATION MIDDLEWARE
// ================================

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token proporcionado' });

  const token = auth.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token malformado' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (!decoded.id || !decoded.rol) {
      return res.status(401).json({ error: 'Token inválido' });
    }
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

async function adminOnly(req, res, next) {
  if (!req.user || req.user.rol !== 'admin') {
    console.warn(`⚠️ Intento de acceso no autorizado a área admin por usuario: ${req.user?.usuario || 'desconocido'}`);
    return res.status(403).json({ error: 'Acceso denegado. Solo administradores.' });
  }
  try {
    const db=await getDB();
    const [[current]]=await db.execute('SELECT id, rol, verificado, lockedUntil, usuario FROM users WHERE id = ?', [req.user.id]);
    if(!current || current.rol!=='admin' || Number(current.verificado)!==1 || (current.lockedUntil && new Date(current.lockedUntil).getTime()>Date.now())){
      return res.status(403).json({error:'Tu cuenta ya no tiene permisos de administrador activos. Vuelve a iniciar sesión.'});
    }
    req.user={...req.user,rol:current.rol,usuario:current.usuario||req.user.usuario};
    next();
  }catch(error){
    console.error('No se pudieron comprobar los permisos de administración:',error.code||error.name);
    return res.status(503).json({error:'No pudimos comprobar tus permisos. Intenta nuevamente.'});
  }
}

module.exports = { authMiddleware, adminOnly };
