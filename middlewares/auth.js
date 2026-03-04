const jwt = require('jsonwebtoken');

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

function adminOnly(req, res, next) {
  if (!req.user || req.user.rol !== 'admin') {
    console.warn(`⚠️ Intento de acceso no autorizado a área admin por usuario: ${req.user?.usuario || 'desconocido'}`);
    return res.status(403).json({ error: 'Acceso denegado. Solo administradores.' });
  }
  next();
}

module.exports = { authMiddleware, adminOnly };
