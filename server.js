const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
require('dotenv').config();

const app = express();
app.set('trust proxy', 1);

// ================================
// 🛡️ SEGURIDAD - MIDDLEWARES
// ================================

// Helmet: protege contra vulnerabilidades comunes
app.use(helmet());

// CORS configurado correctamente
const allowedOrigins = [
  "https://sportlikeapps.netlify.app",
  "http://localhost:1234"
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true); // permitir Postman/server
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    } else {
      return callback(new Error("CORS no permitido"));
    }
  },
  credentials: true
}));


// Rate limiting para prevenir brute force
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 5, // 5 intentos
  message: { error: 'Demasiados intentos de login. Intenta en 15 minutos.' }
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Demasiadas peticiones. Intenta más tarde.' }
});

app.use('/api/login', loginLimiter);
app.use('/api/', generalLimiter);

app.use(bodyParser.json({ limit: '10mb' }));
app.use(passport.initialize());

// ================================
// 🔐 JWT SECRET VALIDATION
// ================================

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET || JWT_SECRET === 'change_this_secret') {
  console.error('❌ ERROR: JWT_SECRET no configurado o usando valor por defecto inseguro');
  process.exit(1);
}

// ================================
// 🗄️ DATABASE
// ================================

async function getDB() {
  return mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
  });
}

// ================================
// 🔒 VALIDACIONES Y SANITIZACIÓN
// ================================

function sanitizeInput(input) {
  if (typeof input !== 'string') return input;
  // Remover caracteres peligrosos para SQL injection
  return input.trim().replace(/['"`;\\]/g, '');
}

function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

function validatePassword(password) {
  // Mínimo 8 caracteres, 1 mayúscula, 1 minúscula, 1 número, 1 especial
  const re = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  return re.test(password);
}

function validateUsername(usuario) {
  // Solo letras, números, guiones y guiones bajos, 4-20 caracteres
  const re = /^[a-zA-Z0-9_-]{4,20}$/;
  return re.test(usuario);
}

function generarPasswordAleatoria(longitud = 12) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%&*';
  let pass = '';
  for (let i = 0; i < longitud; i++) {
    pass += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return pass;
}

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
    
    // Validar que el token tenga los campos necesarios
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

// ================================
// 🔐 GOOGLE OAUTH
// ================================

passport.use(new GoogleStrategy(
  {
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      const db = await getDB();
      const correo = profile.emails[0].value;
      
      // Validar email
      if (!validateEmail(correo)) {
        return done(new Error('Email inválido'), null);
      }
      
      const [rows] = await db.execute('SELECT * FROM users WHERE correo = ?', [correo]);
      
      let user;
      
      if (rows.length > 0) {
        user = rows[0];
      } else {
        const tempPassword = generarPasswordAleatoria();
        const hash = await bcrypt.hash(tempPassword, 10);
        
        const nombreCompleto = profile.displayName || 'Usuario';
        const partesNombre = nombreCompleto.trim().split(' ');
        
        const nombre = sanitizeInput(partesNombre[0] || 'Usuario');
        const apellidoP = sanitizeInput(partesNombre[1] || 'Google');
        const apellidoM = sanitizeInput(partesNombre[2] || '');
        
        const usuarioBase = correo.split('@')[0];
        let usuario = sanitizeInput(usuarioBase);
        let contador = 1;
        
        while (true) {
          const [existente] = await db.execute('SELECT id FROM users WHERE usuario = ?', [usuario]);
          if (existente.length === 0) break;
          usuario = sanitizeInput(`${usuarioBase}${contador}`);
          contador++;
        }
        
        const [result] = await db.execute(
          `INSERT INTO users (nombre, apellidoP, apellidoM, correo, usuario, password, rol, verificado, createdAt, updatedAt)
           VALUES (?,?,?,?,?,?,?,1,NOW(),NOW())`,
          [nombre, apellidoP, apellidoM, correo, usuario, hash, 'cliente']
        );
        
        user = {
          id: result.insertId,
          nombre: nombre,
          apellidoP: apellidoP,
          apellidoM: apellidoM,
          correo,
          usuario: usuario,
          rol: 'cliente'
        };
      }
      
      // IMPORTANTE: Nunca permitir que un login por Google tenga rol admin
      if (user.rol === 'admin') {
        user.rol = 'cliente';
      }
      
      const token = jwt.sign(
        { 
          id: user.id, 
          usuario: user.usuario, 
          rol: user.rol,
          correo: user.correo, 
          nombre: user.nombre,
          apellidoP: user.apellidoP,
          apellidoM: user.apellidoM
        },
        JWT_SECRET,
        { expiresIn: '7d' }
      );
      
      done(null, token);
    } catch (err) {
      console.error('Error en Google OAuth:', err);
      done(err, null);
    }
  }
));

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', passport.authenticate('google', { session: false }), (req, res) => {
  const token = req.user;
  res.redirect(`${process.env.CLIENT_URL}/google-callback?token=${token}`);
});

// ================================
// 📍 ENDPOINTS
// ================================

app.get('/', (req, res) => res.send('Servidor SportLike funcionando correctamente'));

// ================================
// 🔐 REGISTRO
// ================================

app.post('/api/register', async (req, res) => {
  const { nombre, apellidoP, apellidoM, fechaNac, correo, telefono, usuario, password, rol } = req.body;
  
  // Validaciones
  if (!nombre || !apellidoP || !usuario || !correo || !password) {
    return res.status(400).json({ error: 'Faltan campos requeridos' });
  }
  
  if (!validateEmail(correo)) {
    return res.status(400).json({ error: 'Email inválido' });
  }
  
  if (!validateUsername(usuario)) {
    return res.status(400).json({ error: 'Usuario inválido. Debe tener 4-20 caracteres alfanuméricos' });
  }
  
  if (!validatePassword(password)) {
    return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula, un número y un carácter especial' });
  }
  
  // 🚨 SEGURIDAD: Nunca permitir registro como admin desde el formulario
  const rolFinal = 'cliente';
  
  try {
    const db = await getDB();
    
    // Sanitizar inputs
    const nombreSafe = sanitizeInput(nombre);
    const apellidoPSafe = sanitizeInput(apellidoP);
    const apellidoMSafe = apellidoM ? sanitizeInput(apellidoM) : null;
    const usuarioSafe = sanitizeInput(usuario);
    const correoSafe = sanitizeInput(correo);
    const telefonoSafe = telefono ? sanitizeInput(telefono) : null;
    
    const [existing] = await db.execute(
      'SELECT id FROM users WHERE usuario = ? OR correo = ? OR telefono = ?', 
      [usuarioSafe, correoSafe, telefonoSafe]
    );
    
    if (existing.length > 0) {
      return res.status(400).json({ error: 'Usuario, correo o teléfono ya registrado' });
    }
    
    const hash = await bcrypt.hash(password, 12); // Aumentar rounds a 12
    
    const [result] = await db.execute(
      `INSERT INTO users (nombre, apellidoP, apellidoM, fechaNac, correo, telefono, usuario, password, rol, verificado, createdAt, updatedAt)
       VALUES (?,?,?,?,?,?,?,?,?,0,NOW(),NOW())`,
      [nombreSafe, apellidoPSafe, apellidoMSafe, fechaNac || null, correoSafe, telefonoSafe, usuarioSafe, hash, rolFinal]
    );
    
    const token = jwt.sign({ id: result.insertId, correo: correoSafe }, JWT_SECRET, { expiresIn: '1d' });
    
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: process.env.EMAIL_PORT,
      secure: false,
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
    });
    
    const verifyLink = `${process.env.CLIENT_URL}/verify-email?token=${token}`;
    
    await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: correoSafe,
      subject: 'Verifica tu correo - SportLike',
      html: `<p>Hola ${nombreSafe},</p><p>Para activar tu cuenta, haz clic en el siguiente enlace:</p><a href="${verifyLink}">Verificar correo</a><p>Si no creaste esta cuenta, ignora este correo.</p>`
    });
    
    res.json({ message: 'Usuario registrado correctamente. Revisa tu correo para activar tu cuenta.' });
  } catch (err) {
    console.error('Error en registro:', err);
    res.status(500).json({ error: 'Error registrando usuario' });
  }
});

// ================================
// 🔐 LOGIN - VERSION SEGURA
// ================================

app.post('/api/login', async (req, res) => {
  const { usuario, password } = req.body;
  
  // Validación básica
  if (!usuario || !password) {
    return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
  }
  
  // Sanitizar input
  const usuarioSafe = sanitizeInput(usuario);

  try {
    const db = await getDB();
    
    // 🔒 IMPORTANTE: Seleccionar solo campos necesarios, incluyendo el rol
    const [rows] = await db.execute(
      'SELECT id, nombre, apellidoP, apellidoM, usuario, correo, password, rol, verificado, failedAttempts, lockedUntil FROM users WHERE usuario = ?', 
      [usuarioSafe]
    );
    
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }

    const user = rows[0];

    // Verificar bloqueo
    if (user.lockedUntil && new Date(user.lockedUntil) > new Date()) {
      const minutos = Math.ceil((new Date(user.lockedUntil) - new Date()) / 60000);
      return res.status(403).json({ error: `Cuenta bloqueada. Intenta en ${minutos} minutos.` });
    }

    // Verificar email
    if (user.verificado === 0) {
      return res.status(403).json({ error: 'Debes verificar tu correo antes de iniciar sesión' });
    }

    // Verificar contraseña
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      const intentos = user.failedAttempts + 1;
      let lock = null;

      if (intentos >= 3) {
        lock = new Date(Date.now() + 30 * 60 * 1000);
        console.warn(`⚠️ Cuenta bloqueada por múltiples intentos fallidos: ${user.usuario}`);
      }

      await db.execute(
        'UPDATE users SET failedAttempts=?, lockedUntil=? WHERE id=?',
        [intentos, lock, user.id]
      );

      if (intentos >= 3) {
        return res.status(403).json({ error: 'Cuenta bloqueada por 30 minutos debido a múltiples intentos fallidos' });
      }

      return res.status(401).json({ error: `Credenciales incorrectas. Intentos restantes: ${3 - intentos}` });
    }

    // Login exitoso: resetear intentos
    await db.execute(
      'UPDATE users SET failedAttempts=0, lockedUntil=NULL WHERE id=?',
      [user.id]
    );

    // 🔒 CREAR TOKEN CON INFORMACIÓN VALIDADA
    const jwtToken = jwt.sign(
      { 
        id: user.id, 
        usuario: user.usuario, 
        rol: user.rol, // El rol viene directamente de la BD
        correo: user.correo,
        nombre: user.nombre
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Log de login exitoso
    console.log(`✅ Login exitoso: ${user.usuario} (${user.rol})`);

    res.json({
      user: {
        id: user.id,
        nombre: user.nombre,
        apellidoP: user.apellidoP,
        apellidoM: user.apellidoM,
        usuario: user.usuario,
        rol: user.rol,
        correo: user.correo
      },
      token: jwtToken
    });

  } catch (err) {
    console.error('Error en login:', err);
    res.status(500).json({ error: 'Error en login' });
  }
});

// ================================
// 📧 VERIFICACIÓN EMAIL
// ================================

app.get('/api/verify-email', async (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(400).send('Token inválido');
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const db = await getDB();
    await db.execute('UPDATE users SET verificado = 1 WHERE id = ?', [decoded.id]);
    res.send('Correo verificado correctamente. Ahora puedes iniciar sesión.');
  } catch {
    res.status(400).send('Token inválido o expirado');
  }
});

// ================================
// 🔑 RECUPERACIÓN DE CONTRASEÑA
// ================================

app.post('/api/forgot-password', async (req, res) => {
  const { correo } = req.body;
  
  if (!correo || !validateEmail(correo)) {
    return res.status(400).json({ error: 'Email inválido' });
  }
  
  const correoSafe = sanitizeInput(correo);
  
  try {
    const db = await getDB();
    const [users] = await db.execute('SELECT id, nombre FROM users WHERE correo = ?', [correoSafe]);
    
    if (users.length === 0) {
      // No revelar si el usuario existe o no
      return res.json({ message: 'Si el correo existe, recibirás un enlace de recuperación' });
    }
    
    const userId = users[0].id;
    const nombre = users[0].nombre;
    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 3600000); // 1 hora
    
    await db.execute(
      'INSERT INTO Token (userId, token, expires, createdAt) VALUES (?, ?, ?, NOW())', 
      [userId, token, expires]
    );
    
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: process.env.EMAIL_PORT,
      secure: false,
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
    });
    
    const resetLink = `${process.env.CLIENT_URL}/reset-password?token=${token}`;
    
    await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: correoSafe,
      subject: 'Recuperación de contraseña - SportLike',
      html: `<p>Hola ${nombre},</p><p>Has solicitado restablecer tu contraseña. Haz clic en el siguiente enlace (válido por 1 hora):</p><a href="${resetLink}">Restablecer contraseña</a><p>Si no solicitaste esto, ignora este correo.</p>`
    });
    
    res.json({ message: 'Si el correo existe, recibirás un enlace de recuperación' });
  } catch (err) {
    console.error('Error en forgot-password:', err);
    res.status(500).json({ error: 'Error procesando solicitud' });
  }
});

app.post('/api/reset-password', async (req, res) => {
  const { token, password } = req.body;
  
  if (!token || !password) {
    return res.status(400).json({ error: 'Token y contraseña requeridos' });
  }
  
  if (!validatePassword(password)) {
    return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula, un número y un carácter especial' });
  }
  
  try {
    const db = await getDB();
    const [rows] = await db.execute('SELECT userId, expires FROM Token WHERE token = ?', [token]);
    
    if (rows.length === 0) {
      return res.status(400).json({ error: 'Token inválido' });
    }
    
    const tokenData = rows[0];
    
    if (new Date(tokenData.expires) < new Date()) {
      return res.status(400).json({ error: 'Token expirado' });
    }
    
    const hash = await bcrypt.hash(password, 12);
    await db.execute('UPDATE users SET password = ? WHERE id = ?', [hash, tokenData.userId]);
    await db.execute('DELETE FROM Token WHERE token = ?', [token]);
    
    res.json({ message: 'Contraseña restablecida correctamente' });
  } catch (err) {
    console.error('Error en reset-password:', err);
    res.status(500).json({ error: 'Error restableciendo contraseña' });
  }
});

// ================================
// 👤 PERFIL
// ================================

app.post('/api/update-profile', authMiddleware, async (req, res) => {
  const { nombre, apellidoP, apellidoM, telefono, usuario } = req.body;
  
  if (!nombre || !apellidoP || !usuario) {
    return res.status(400).json({ error: 'Faltan campos requeridos' });
  }
  
  if (!validateUsername(usuario)) {
    return res.status(400).json({ error: 'Usuario inválido' });
  }
  
  // Sanitizar
  const nombreSafe = sanitizeInput(nombre);
  const apellidoPSafe = sanitizeInput(apellidoP);
  const apellidoMSafe = apellidoM ? sanitizeInput(apellidoM) : null;
  const usuarioSafe = sanitizeInput(usuario);
  const telefonoSafe = telefono ? sanitizeInput(telefono) : null;
  
  try {
    const db = await getDB();
    
    const [exists] = await db.execute(
      'SELECT id FROM users WHERE (usuario = ? OR telefono = ?) AND id != ?', 
      [usuarioSafe, telefonoSafe, req.user.id]
    );
    
    if (exists.length > 0) {
      return res.status(400).json({ error: 'Usuario o teléfono ya registrado' });
    }
    
    await db.execute(
      `UPDATE users SET nombre=?, apellidoP=?, apellidoM=?, telefono=?, usuario=?, updatedAt=NOW() WHERE id=?`,
      [nombreSafe, apellidoPSafe, apellidoMSafe, telefonoSafe, usuarioSafe, req.user.id]
    );
    
    res.json({ message: 'Perfil actualizado correctamente' });
  } catch (err) {
    console.error('Error actualizando perfil:', err);
    res.status(500).json({ error: 'Error actualizando perfil' });
  }
});

app.post('/api/update-password', authMiddleware, async (req, res) => {
  const { actual, nueva } = req.body;
  
  if (!actual || !nueva) {
    return res.status(400).json({ error: 'Debes enviar ambas contraseñas' });
  }
  
  if (!validatePassword(nueva)) {
    return res.status(400).json({ error: 'La nueva contraseña no cumple los requisitos de seguridad' });
  }
  
  try {
    const db = await getDB();
    const [rows] = await db.execute('SELECT password FROM users WHERE id=?', [req.user.id]);
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    
    const match = await bcrypt.compare(actual, rows[0].password);
    
    if (!match) {
      return res.status(401).json({ error: 'La contraseña actual es incorrecta' });
    }
    
    const hash = await bcrypt.hash(nueva, 12);
    await db.execute('UPDATE users SET password=?, updatedAt=NOW() WHERE id=?', [hash, req.user.id]);
    
    res.json({ message: 'Contraseña actualizada correctamente' });
  } catch (err) {
    console.error('Error actualizando contraseña:', err);
    res.status(500).json({ error: 'Error actualizando contraseña' });
  }
});

// ================================
// 👥 ADMIN - USUARIOS (BÁSICO)
// ================================

app.get('/api/users', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute('SELECT id, nombre, apellidoP, apellidoM, correo, usuario, rol FROM users');
    res.json(rows);
  } catch (err) {
    console.error('Error obteniendo usuarios:', err);
    res.status(500).json({ error: 'Error al obtener usuarios' });
  }
});

app.get("/api/me", authMiddleware, async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(
      "SELECT id, nombre, apellidoP, apellidoM, usuario, correo, rol FROM users WHERE id = ?",
      [req.user.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: "Usuario no existe" });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error('Error obteniendo usuario:', err);
    res.status(500).json({ error: "Error obteniendo usuario" });
  }
});

// ================================
// 📊 ADMIN - DASHBOARD
// ================================

app.get("/api/admin/dashboard", authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const { from, to, branch } = req.query;

    let where = [];
    let params = [];

    if (from) {
      where.push("o.fecha >= ?");
      params.push(from);
    }

    if (to) {
      where.push("o.fecha <= ?");
      params.push(to);
    }

    if (branch && branch !== "all") {
      where.push("o.sucursal = ?");
      params.push(branch);
    }

    const whereSQL = where.length ? "WHERE " + where.join(" AND ") : "";

    const [timeline] = await db.execute(`
      SELECT 
        DATE(o.fecha) AS dia,
        SUM(o.total) AS total
      FROM orders o
      ${whereSQL}
      GROUP BY dia
      ORDER BY dia;
    `, params);

    const [branches] = await db.execute(`
      SELECT 
        o.sucursal,
        SUM(o.total) AS ingresos
      FROM orders o
      ${whereSQL}
      GROUP BY o.sucursal
      ORDER BY ingresos DESC;
    `, params);

    const [topProducts] = await db.execute(`
      SELECT 
        p.nombre,
        SUM(oi.cantidad) AS vendidos,
        SUM(oi.subtotal) AS ingresos
      FROM order_items oi
      JOIN products p ON p.id = oi.product_id
      JOIN orders o ON o.id = oi.order_id
      ${whereSQL}
      GROUP BY p.nombre
      ORDER BY vendidos DESC
      LIMIT 10;
    `, params);

    res.json({
      salesTimeline: timeline,
      branchRanking: branches,
      topProducts
    });
  } catch (err) {
    console.error("Error en dashboard admin:", err);
    res.status(500).json({ error: "Error generando dashboard admin" });
  }
});

// ================================
// 🛍️ PÚBLICO - PRODUCTOS PARA CATÁLOGO
// ================================

app.get("/api/products", async (req, res) => {
  const { q, categoria } = req.query;

  try {
    const db = await getDB();

    let sql = `
      SELECT 
        p.id,
        p.nombre,
        p.descripcion,
        p.precio,
        p.categoria,
        p.imagen,
        COALESCE(SUM(i.stock), 0) AS stock_total
      FROM products p
      LEFT JOIN inventory i ON i.product_id = p.id
      WHERE p.activo = 1
    `;

    const params = [];

    if (q) {
      sql += " AND (p.nombre LIKE ? OR p.descripcion LIKE ?)";
      params.push(`%${q}%`, `%${q}%`);
    }

    if (categoria) {
      sql += " AND p.categoria = ?";
      params.push(categoria);
    }

    sql += " GROUP BY p.id ORDER BY p.nombre";

    const [rows] = await db.execute(sql, params);
    res.json(rows);
  } catch (err) {
    console.error("Error obteniendo productos públicos:", err);
    res.status(500).json({ error: "Error obteniendo productos" });
  }
});

// Categorías públicas
app.get("/api/categories", async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT DISTINCT categoria AS nombre
      FROM products
      WHERE activo = 1 AND categoria IS NOT NULL AND categoria != ''
      ORDER BY categoria
    `);
    res.json(rows.map(r => r.nombre));
  } catch (err) {
    res.status(500).json({ error: "Error obteniendo categorías" });
  }
});


// ================================
// ADMIN - PRODUCTOS
// ================================

// 📋 OBTENER TODOS LOS PRODUCTOS (CON STOCK TOTAL)
app.get("/api/admin/products", authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT 
        p.id, 
        p.nombre, 
        p.descripcion, 
        p.precio, 
        p.categoria, 
        p.imagen, 
        p.activo,
        p.createdAt,
        p.updatedAt,
        COALESCE(SUM(i.stock), 0) AS stock_total,
        COUNT(DISTINCT i.branch_id) AS sucursales_con_stock
      FROM products p
      LEFT JOIN inventory i ON i.product_id = p.id
      GROUP BY p.id
      ORDER BY p.id DESC
    `);
    res.json(rows);
  } catch (err) {
    console.error('Error obteniendo productos:', err);
    res.status(500).json({ error: "Error obteniendo productos" });
  }
});

// 📄 OBTENER UN PRODUCTO ESPECÍFICO
app.get("/api/admin/products/:id", authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT 
        p.*,
        COALESCE(SUM(i.stock), 0) AS stock_total
      FROM products p
      LEFT JOIN inventory i ON i.product_id = p.id
      WHERE p.id = ?
      GROUP BY p.id
    `, [req.params.id]);

    if (rows.length === 0) {
      return res.status(404).json({ error: "Producto no encontrado" });
    }

    // Obtener inventario por sucursal
    const [inventory] = await db.execute(`
      SELECT 
        i.id,
        i.stock,
        i.min_stock,
        b.id AS branch_id,
        b.nombre AS sucursal
      FROM inventory i
      JOIN branches b ON b.id = i.branch_id
      WHERE i.product_id = ?
    `, [req.params.id]);

    res.json({
      product: rows[0],
      inventory: inventory
    });
  } catch (err) {
    console.error('Error obteniendo producto:', err);
    res.status(500).json({ error: "Error obteniendo producto" });
  }
});

// ➕ CREAR PRODUCTO (CON INVENTARIO INICIAL)
app.post("/api/admin/products", authMiddleware, adminOnly, async (req, res) => {
  const { nombre, descripcion, precio, categoria, imagen, inventario } = req.body;

  // Validaciones
  if (!nombre || !precio) {
    return res.status(400).json({ error: "Nombre y precio obligatorios" });
  }

  if (precio < 0) {
    return res.status(400).json({ error: "El precio no puede ser negativo" });
  }

  // Sanitizar inputs
  const nombreSafe = sanitizeInput(nombre);
  const descripcionSafe = descripcion ? sanitizeInput(descripcion) : null;
  const categoriaSafe = categoria ? sanitizeInput(categoria) : null;

  try {
    const db = await getDB();
    
    // Insertar producto
    const [result] = await db.execute(`
      INSERT INTO products
      (nombre, descripcion, precio, categoria, imagen, activo, createdAt, updatedAt)
      VALUES (?,?,?,?,?,1,NOW(),NOW())
    `, [nombreSafe, descripcionSafe, precio, categoriaSafe, imagen]);

    const productId = result.insertId;

    // Si se proporcionó inventario inicial, agregarlo
    if (inventario && Array.isArray(inventario) && inventario.length > 0) {
      for (const inv of inventario) {
        if (inv.branch_id && inv.stock !== undefined) {
          await db.execute(`
            INSERT INTO inventory (product_id, branch_id, stock, min_stock)
            VALUES (?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE stock = VALUES(stock), min_stock = VALUES(min_stock)
          `, [productId, inv.branch_id, inv.stock, inv.min_stock || 10]);
        }
      }
    }

    console.log(`✅ Producto creado: ${nombreSafe} (ID: ${productId}) por usuario ${req.user.usuario}`);
    res.json({ 
      message: "Producto creado correctamente",
      productId: productId
    });
  } catch (err) {
    console.error('Error creando producto:', err);
    res.status(500).json({ error: "Error creando producto" });
  }
});

// ✏️ ACTUALIZAR PRODUCTO
app.put("/api/admin/products/:id", authMiddleware, adminOnly, async (req, res) => {
  const { nombre, descripcion, precio, categoria, imagen, activo } = req.body;

  // Validaciones
  if (!nombre || precio === undefined) {
    return res.status(400).json({ error: "Nombre y precio son obligatorios" });
  }

  if (precio < 0) {
    return res.status(400).json({ error: "El precio no puede ser negativo" });
  }

  // Sanitizar
  const nombreSafe = sanitizeInput(nombre);
  const descripcionSafe = descripcion ? sanitizeInput(descripcion) : null;
  const categoriaSafe = categoria ? sanitizeInput(categoria) : null;

  try {
    const db = await getDB();
    
    // Verificar que el producto existe
    const [exists] = await db.execute('SELECT id FROM products WHERE id = ?', [req.params.id]);
    
    if (exists.length === 0) {
      return res.status(404).json({ error: "Producto no encontrado" });
    }

    await db.execute(`
      UPDATE products
      SET nombre=?, descripcion=?, precio=?, categoria=?, imagen=?, activo=?, updatedAt=NOW()
      WHERE id=?
    `, [nombreSafe, descripcionSafe, precio, categoriaSafe, imagen, activo, req.params.id]);

    console.log(`✅ Producto actualizado: ID ${req.params.id} por usuario ${req.user.usuario}`);
    res.json({ message: "Producto actualizado correctamente" });
  } catch (err) {
    console.error('Error actualizando producto:', err);
    res.status(500).json({ error: "Error actualizando producto" });
  }
});

// 🗑️ ELIMINAR PRODUCTO (SOFT DELETE)
app.delete("/api/admin/products/:id", authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    
    // Verificar que el producto existe
    const [exists] = await db.execute('SELECT id, nombre FROM products WHERE id = ?', [req.params.id]);
    
    if (exists.length === 0) {
      return res.status(404).json({ error: "Producto no encontrado" });
    }

    // Desactivar producto (soft delete)
    await db.execute(`
      UPDATE products
      SET activo = 0, updatedAt = NOW()
      WHERE id = ?
    `, [req.params.id]);

    console.log(`⚠️ Producto desactivado: ${exists[0].nombre} (ID: ${req.params.id}) por usuario ${req.user.usuario}`);
    res.json({ message: "Producto desactivado correctamente" });
  } catch (err) {
    console.error('Error eliminando producto:', err);
    res.status(500).json({ error: "Error eliminando producto" });
  }
});

// 🔄 REACTIVAR PRODUCTO
app.patch("/api/admin/products/:id/reactivate", authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    
    const [exists] = await db.execute('SELECT id, nombre FROM products WHERE id = ?', [req.params.id]);
    
    if (exists.length === 0) {
      return res.status(404).json({ error: "Producto no encontrado" });
    }

    await db.execute(`
      UPDATE products
      SET activo = 1, updatedAt = NOW()
      WHERE id = ?
    `, [req.params.id]);

    console.log(`✅ Producto reactivado: ${exists[0].nombre} (ID: ${req.params.id}) por usuario ${req.user.usuario}`);
    res.json({ message: "Producto reactivado correctamente" });
  } catch (err) {
    console.error('Error reactivando producto:', err);
    res.status(500).json({ error: "Error reactivando producto" });
  }
});

// 🗑️ ELIMINAR PERMANENTEMENTE (HARD DELETE)
app.delete("/api/admin/products/:id/permanent", authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    
    const [exists] = await db.execute('SELECT id, nombre FROM products WHERE id = ?', [req.params.id]);
    
    if (exists.length === 0) {
      return res.status(404).json({ error: "Producto no encontrado" });
    }

    // Primero eliminar inventario relacionado
    await db.execute('DELETE FROM inventory WHERE product_id = ?', [req.params.id]);
    
    // Luego eliminar el producto
    await db.execute('DELETE FROM products WHERE id = ?', [req.params.id]);

    console.log(`🗑️ Producto eliminado permanentemente: ${exists[0].nombre} (ID: ${req.params.id}) por usuario ${req.user.usuario}`);
    res.json({ message: "Producto eliminado permanentemente" });
  } catch (err) {
    console.error('Error eliminando producto permanentemente:', err);
    res.status(500).json({ error: "Error eliminando producto permanentemente" });
  }
});

// 📊 OBTENER CATEGORÍAS DISPONIBLES
app.get("/api/admin/categories", authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT DISTINCT categoria AS nombre, COUNT(*) AS productos
      FROM products
      WHERE categoria IS NOT NULL AND categoria != ''
      GROUP BY categoria
      ORDER BY categoria
    `);
    res.json(rows);
  } catch (err) {
    console.error('Error obteniendo categorías:', err);
    res.status(500).json({ error: "Error obteniendo categorías" });
  }
});

// 🔍 BUSCAR PRODUCTOS (ADMIN)
app.get("/api/admin/products/search", authMiddleware, adminOnly, async (req, res) => {
  const { q, categoria, activo } = req.query;

  try {
    const db = await getDB();
    
    let sql = `
      SELECT 
        p.id, 
        p.nombre, 
        p.descripcion, 
        p.precio, 
        p.categoria, 
        p.imagen, 
        p.activo,
        COALESCE(SUM(i.stock), 0) AS stock_total
      FROM products p
      LEFT JOIN inventory i ON i.product_id = p.id
      WHERE 1=1
    `;
    
    const params = [];

    if (q) {
      sql += " AND (p.nombre LIKE ? OR p.descripcion LIKE ?)";
      params.push(`%${q}%`, `%${q}%`);
    }

    if (categoria) {
      sql += " AND p.categoria = ?";
      params.push(categoria);
    }

    if (activo !== undefined) {
      sql += " AND p.activo = ?";
      params.push(activo);
    }

    sql += " GROUP BY p.id ORDER BY p.nombre";

    const [rows] = await db.execute(sql, params);
    res.json(rows);
  } catch (err) {
    console.error('Error buscando productos:', err);
    res.status(500).json({ error: "Error buscando productos" });
  }
});

// 📦 ACTUALIZAR INVENTARIO DE UN PRODUCTO EN MÚLTIPLES SUCURSALES
app.put("/api/admin/products/:id/inventory", authMiddleware, adminOnly, async (req, res) => {
  const { inventario } = req.body;

  if (!inventario || !Array.isArray(inventario)) {
    return res.status(400).json({ error: "Debe proporcionar un array de inventario" });
  }

  try {
    const db = await getDB();

    // Verificar que el producto existe
    const [exists] = await db.execute('SELECT id FROM products WHERE id = ?', [req.params.id]);
    
    if (exists.length === 0) {
      return res.status(404).json({ error: "Producto no encontrado" });
    }

    // Actualizar inventario para cada sucursal
    for (const inv of inventario) {
      if (inv.branch_id && inv.stock !== undefined) {
        await db.execute(`
          INSERT INTO inventory (product_id, branch_id, stock, min_stock)
          VALUES (?, ?, ?, ?)
          ON DUPLICATE KEY UPDATE stock = VALUES(stock), min_stock = VALUES(min_stock)
        `, [req.params.id, inv.branch_id, inv.stock, inv.min_stock || 10]);
      }
    }

    console.log(`✅ Inventario actualizado para producto ID ${req.params.id} por usuario ${req.user.usuario}`);
    res.json({ message: "Inventario actualizado correctamente" });
  } catch (err) {
    console.error('Error actualizando inventario del producto:', err);
    res.status(500).json({ error: "Error actualizando inventario" });
  }
});


// ================================
// 📦 ADMIN - INVENTARIO (MEJORADO)
// ================================

// 📋 OBTENER TODO EL INVENTARIO
app.get("/api/admin/inventory", authMiddleware, adminOnly, async (req, res) => {
  const { branch, low_stock } = req.query;

  try {
    const db = await getDB();

    let sql = `
      SELECT 
        i.id,
        i.product_id,
        i.branch_id,
        b.nombre AS sucursal,
        p.nombre AS producto,
        p.precio,
        p.categoria,
        p.imagen,
        p.activo AS producto_activo,
        i.stock,
        i.min_stock,
        CASE 
          WHEN i.stock = 0 THEN 'sin_stock'
          WHEN i.stock <= i.min_stock THEN 'bajo_stock'
          ELSE 'disponible'
        END AS estado
      FROM inventory i
      JOIN products p ON p.id = i.product_id
      JOIN branches b ON b.id = i.branch_id
      WHERE 1=1
    `;

    let params = [];

    if (branch && branch !== "all") {
      sql += " AND i.branch_id = ?";
      params.push(branch);
    }

    if (low_stock === "true") {
      sql += " AND i.stock <= i.min_stock";
    }

    sql += " ORDER BY b.nombre, p.nombre";

    const [rows] = await db.execute(sql, params);
    res.json(rows);
  } catch (err) {
    console.error('Error obteniendo inventario:', err);
    res.status(500).json({ error: "Error obteniendo inventario" });
  }
});

// 📊 OBTENER ESTADÍSTICAS DE INVENTARIO
app.get("/api/admin/inventory/stats", authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();

    const [stats] = await db.execute(`
      SELECT 
        COUNT(DISTINCT i.product_id) AS total_productos,
        COUNT(DISTINCT i.branch_id) AS total_sucursales,
        SUM(i.stock) AS stock_total,
        SUM(CASE WHEN i.stock = 0 THEN 1 ELSE 0 END) AS productos_sin_stock,
        SUM(CASE WHEN i.stock > 0 AND i.stock <= i.min_stock THEN 1 ELSE 0 END) AS productos_bajo_stock,
        SUM(i.stock * p.precio) AS valor_inventario
      FROM inventory i
      JOIN products p ON p.id = i.product_id
    `);

    const [porSucursal] = await db.execute(`
      SELECT 
        b.nombre AS sucursal,
        COUNT(DISTINCT i.product_id) AS productos,
        SUM(i.stock) AS stock_total,
        SUM(i.stock * p.precio) AS valor_inventario
      FROM inventory i
      JOIN branches b ON b.id = i.branch_id
      JOIN products p ON p.id = i.product_id
      GROUP BY b.id, b.nombre
      ORDER BY valor_inventario DESC
    `);

    res.json({
      general: stats[0],
      porSucursal: porSucursal
    });
  } catch (err) {
    console.error('Error obteniendo estadísticas de inventario:', err);
    res.status(500).json({ error: "Error obteniendo estadísticas" });
  }
});

// ✏️ ACTUALIZAR INVENTARIO INDIVIDUAL
app.put("/api/admin/inventory/:id", authMiddleware, adminOnly, async (req, res) => {
  const { stock, min_stock } = req.body;

  if (stock === undefined || stock < 0) {
    return res.status(400).json({ error: "Stock inválido" });
  }

  if (min_stock !== undefined && min_stock < 0) {
    return res.status(400).json({ error: "Stock mínimo inválido" });
  }

  try {
    const db = await getDB();
    
    // Verificar que el registro existe
    const [exists] = await db.execute(`
      SELECT i.id, p.nombre AS producto, b.nombre AS sucursal
      FROM inventory i
      JOIN products p ON p.id = i.product_id
      JOIN branches b ON b.id = i.branch_id
      WHERE i.id = ?
    `, [req.params.id]);

    if (exists.length === 0) {
      return res.status(404).json({ error: "Registro de inventario no encontrado" });
    }

    await db.execute(`
      UPDATE inventory
      SET stock=?, min_stock=?
      WHERE id=?
    `, [stock, min_stock || 10, req.params.id]);

    console.log(`✅ Inventario actualizado: ${exists[0].producto} en ${exists[0].sucursal} por usuario ${req.user.usuario}`);
    res.json({ message: "Inventario actualizado correctamente" });
  } catch (err) {
    console.error('Error actualizando inventario:', err);
    res.status(500).json({ error: "Error actualizando inventario" });
  }
});

// ➕ AGREGAR PRODUCTO A SUCURSAL
app.post("/api/admin/inventory", authMiddleware, adminOnly, async (req, res) => {
  const { product_id, branch_id, stock, min_stock } = req.body;

  if (!product_id || !branch_id || stock === undefined) {
    return res.status(400).json({ error: "Faltan campos obligatorios" });
  }

  if (stock < 0) {
    return res.status(400).json({ error: "El stock no puede ser negativo" });
  }

  try {
    const db = await getDB();

    // Verificar que el producto existe y está activo
    const [product] = await db.execute('SELECT id, nombre, activo FROM products WHERE id = ?', [product_id]);
    
    if (product.length === 0) {
      return res.status(404).json({ error: "Producto no encontrado" });
    }

    if (product[0].activo === 0) {
      return res.status(400).json({ error: "No se puede agregar inventario a un producto inactivo" });
    }

    // Verificar que la sucursal existe
    const [branch] = await db.execute('SELECT id, nombre FROM branches WHERE id = ?', [branch_id]);
    
    if (branch.length === 0) {
      return res.status(404).json({ error: "Sucursal no encontrada" });
    }

    // Verificar si ya existe inventario para este producto en esta sucursal
    const [exists] = await db.execute(`
      SELECT id FROM inventory WHERE product_id = ? AND branch_id = ?
    `, [product_id, branch_id]);

    if (exists.length > 0) {
      return res.status(400).json({ error: "Este producto ya tiene inventario en esta sucursal. Use actualizar en su lugar." });
    }

    // Insertar inventario
    await db.execute(`
      INSERT INTO inventory (product_id, branch_id, stock, min_stock)
      VALUES (?, ?, ?, ?)
    `, [product_id, branch_id, stock, min_stock || 10]);

    console.log(`✅ Inventario creado: ${product[0].nombre} en ${branch[0].nombre} por usuario ${req.user.usuario}`);
    res.json({ message: "Inventario agregado correctamente" });
  } catch (err) {
    console.error('Error agregando inventario:', err);
    res.status(500).json({ error: "Error agregando inventario" });
  }
});

// 🗑️ ELIMINAR INVENTARIO DE UNA SUCURSAL
app.delete("/api/admin/inventory/:id", authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();

    const [exists] = await db.execute(`
      SELECT i.id, p.nombre AS producto, b.nombre AS sucursal
      FROM inventory i
      JOIN products p ON p.id = i.product_id
      JOIN branches b ON b.id = i.branch_id
      WHERE i.id = ?
    `, [req.params.id]);

    if (exists.length === 0) {
      return res.status(404).json({ error: "Registro de inventario no encontrado" });
    }

    await db.execute('DELETE FROM inventory WHERE id = ?', [req.params.id]);

    console.log(`🗑️ Inventario eliminado: ${exists[0].producto} de ${exists[0].sucursal} por usuario ${req.user.usuario}`);
    res.json({ message: "Inventario eliminado correctamente" });
  } catch (err) {
    console.error('Error eliminando inventario:', err);
    res.status(500).json({ error: "Error eliminando inventario" });
  }
});

// 🔄 TRANSFERIR STOCK ENTRE SUCURSALES
app.post("/api/admin/inventory/transfer", authMiddleware, adminOnly, async (req, res) => {
  const { product_id, from_branch_id, to_branch_id, cantidad } = req.body;

  if (!product_id || !from_branch_id || !to_branch_id || !cantidad) {
    return res.status(400).json({ error: "Faltan campos obligatorios" });
  }

  if (cantidad <= 0) {
    return res.status(400).json({ error: "La cantidad debe ser mayor a 0" });
  }

  if (from_branch_id === to_branch_id) {
    return res.status(400).json({ error: "No se puede transferir a la misma sucursal" });
  }

  try {
    const db = await getDB();

    // Iniciar transacción
    await db.execute('START TRANSACTION');

    try {
      // Verificar inventario origen
      const [origen] = await db.execute(`
        SELECT i.id, i.stock, b.nombre AS sucursal, p.nombre AS producto
        FROM inventory i
        JOIN branches b ON b.id = i.branch_id
        JOIN products p ON p.id = i.product_id
        WHERE i.product_id = ? AND i.branch_id = ?
      `, [product_id, from_branch_id]);

      if (origen.length === 0) {
        throw new Error("No existe inventario en la sucursal origen");
      }

      if (origen[0].stock < cantidad) {
        throw new Error(`Stock insuficiente en ${origen[0].sucursal}. Disponible: ${origen[0].stock}`);
      }

      // Verificar inventario destino
      const [destino] = await db.execute(`
        SELECT i.id, b.nombre AS sucursal
        FROM inventory i
        JOIN branches b ON b.id = i.branch_id
        WHERE i.product_id = ? AND i.branch_id = ?
      `, [product_id, to_branch_id]);

      // Restar del origen
      await db.execute(`
        UPDATE inventory SET stock = stock - ? WHERE id = ?
      `, [cantidad, origen[0].id]);

      // Agregar al destino
      if (destino.length > 0) {
        await db.execute(`
          UPDATE inventory SET stock = stock + ? WHERE id = ?
        `, [cantidad, destino[0].id]);
      } else {
        await db.execute(`
          INSERT INTO inventory (product_id, branch_id, stock, min_stock)
          VALUES (?, ?, ?, 10)
        `, [product_id, to_branch_id, cantidad]);
      }

      // Confirmar transacción
      await db.execute('COMMIT');

      console.log(`✅ Transferencia completada: ${cantidad} unidades de ${origen[0].producto} de ${origen[0].sucursal} a ${destino[0]?.sucursal || 'nueva sucursal'} por usuario ${req.user.usuario}`);
      res.json({ message: "Transferencia completada exitosamente" });

    } catch (error) {
      await db.execute('ROLLBACK');
      throw error;
    }

  } catch (err) {
    console.error('Error en transferencia:', err);
    res.status(500).json({ error: err.message || "Error realizando transferencia" });
  }
});

// ================================
// 🏪 ADMIN - SUCURSALES
// ================================

// 📋 OBTENER TODAS LAS SUCURSALES
app.get("/api/admin/branches", authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT 
        b.id,
        b.nombre,
        b.direccion,
        b.telefono,
        b.activo,
        b.createdAt,
        COUNT(DISTINCT i.product_id) AS productos,
        COALESCE(SUM(i.stock), 0) AS stock_total
      FROM branches b
      LEFT JOIN inventory i ON i.branch_id = b.id
      GROUP BY b.id
      ORDER BY b.nombre
    `);
    res.json(rows);
  } catch (err) {
    console.error('Error obteniendo sucursales:', err);
    res.status(500).json({ error: "Error obteniendo sucursales" });
  }
});

// ➕ CREAR SUCURSAL
app.post("/api/admin/branches", authMiddleware, adminOnly, async (req, res) => {
  const { nombre, direccion, telefono } = req.body;

  if (!nombre || !direccion) {
    return res.status(400).json({ error: "Nombre y dirección obligatorios" });
  }

  const nombreSafe = sanitizeInput(nombre);
  const direccionSafe = sanitizeInput(direccion);
  const telefonoSafe = telefono ? sanitizeInput(telefono) : null;

  try {
    const db = await getDB();

    const [exists] = await db.execute('SELECT id FROM branches WHERE nombre = ?', [nombreSafe]);
    
    if (exists.length > 0) {
      return res.status(400).json({ error: "Ya existe una sucursal con ese nombre" });
    }

    await db.execute(`
      INSERT INTO branches (nombre, direccion, telefono, activo, createdAt)
      VALUES (?, ?, ?, 1, NOW())
    `, [nombreSafe, direccionSafe, telefonoSafe]);

    console.log(`✅ Sucursal creada: ${nombreSafe} por usuario ${req.user.usuario}`);
    res.json({ message: "Sucursal creada correctamente" });
  } catch (err) {
    console.error('Error creando sucursal:', err);
    res.status(500).json({ error: "Error creando sucursal" });
  }
});

// ✏️ ACTUALIZAR SUCURSAL
app.put("/api/admin/branches/:id", authMiddleware, adminOnly, async (req, res) => {
  const { nombre, direccion, telefono, activo } = req.body;

  if (!nombre || !direccion) {
    return res.status(400).json({ error: "Nombre y dirección obligatorios" });
  }

  const nombreSafe = sanitizeInput(nombre);
  const direccionSafe = sanitizeInput(direccion);
  const telefonoSafe = telefono ? sanitizeInput(telefono) : null;

  try {
    const db = await getDB();

    const [exists] = await db.execute('SELECT id FROM branches WHERE id = ?', [req.params.id]);
    
    if (exists.length === 0) {
      return res.status(404).json({ error: "Sucursal no encontrada" });
    }

    await db.execute(`
      UPDATE branches
      SET nombre=?, direccion=?, telefono=?, activo=?
      WHERE id=?
    `, [nombreSafe, direccionSafe, telefonoSafe, activo, req.params.id]);

    console.log(`✅ Sucursal actualizada: ID ${req.params.id} por usuario ${req.user.usuario}`);
    res.json({ message: "Sucursal actualizada correctamente" });
  } catch (err) {
    console.error('Error actualizando sucursal:', err);
    res.status(500).json({ error: "Error actualizando sucursal" });
  }
});

// 🗑️ ELIMINAR SUCURSAL (SOFT DELETE)
app.delete("/api/admin/branches/:id", authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();

    const [exists] = await db.execute('SELECT id, nombre FROM branches WHERE id = ?', [req.params.id]);
    
    if (exists.length === 0) {
      return res.status(404).json({ error: "Sucursal no encontrada" });
    }

    // Verificar si tiene inventario
    const [inventory] = await db.execute('SELECT COUNT(*) as total FROM inventory WHERE branch_id = ?', [req.params.id]);
    
    if (inventory[0].total > 0) {
      return res.status(400).json({ 
        error: "No se puede eliminar una sucursal con inventario. Elimine o transfiera el inventario primero." 
      });
    }

    await db.execute('UPDATE branches SET activo = 0 WHERE id = ?', [req.params.id]);

    console.log(`⚠️ Sucursal desactivada: ${exists[0].nombre} por usuario ${req.user.usuario}`);
    res.json({ message: "Sucursal desactivada correctamente" });
  } catch (err) {
    console.error('Error eliminando sucursal:', err);
    res.status(500).json({ error: "Error eliminando sucursal" });
  }
});


// ================================
// 👥 ADMIN - USUARIOS (MEJORADO)
// ================================

// 📋 OBTENER TODOS LOS USUARIOS (CON FILTROS)
app.get('/api/admin/users', authMiddleware, adminOnly, async (req, res) => {
  const { rol, verificado, search } = req.query;

  try {
    const db = await getDB();
    
    let sql = `
      SELECT 
        id, 
        nombre, 
        apellidoP, 
        apellidoM, 
        correo, 
        telefono,
        usuario, 
        rol,
        verificado,
        failedAttempts,
        lockedUntil,
        createdAt,
        updatedAt
      FROM users
      WHERE 1=1
    `;

    const params = [];

    if (rol && rol !== 'all') {
      sql += " AND rol = ?";
      params.push(rol);
    }

    if (verificado !== undefined) {
      sql += " AND verificado = ?";
      params.push(verificado);
    }

    if (search) {
      sql += " AND (nombre LIKE ? OR apellidoP LIKE ? OR usuario LIKE ? OR correo LIKE ?)";
      const searchTerm = `%${search}%`;
      params.push(searchTerm, searchTerm, searchTerm, searchTerm);
    }

    sql += " ORDER BY createdAt DESC";

    const [rows] = await db.execute(sql, params);
    res.json(rows);
  } catch (err) {
    console.error('Error obteniendo usuarios:', err);
    res.status(500).json({ error: 'Error al obtener usuarios' });
  }
});

// 👤 OBTENER UN USUARIO ESPECÍFICO
app.get('/api/admin/users/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT 
        id, nombre, apellidoP, apellidoM, fechaNac, correo, telefono, usuario, rol, 
        verificado, failedAttempts, lockedUntil, createdAt, updatedAt
      FROM users 
      WHERE id = ?
    `, [req.params.id]);

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    // Obtener órdenes del usuario
    const [orders] = await db.execute(`
      SELECT id, total, fecha, estado, sucursal
      FROM orders
      WHERE user_id = ?
      ORDER BY fecha DESC
      LIMIT 10
    `, [req.params.id]);

    res.json({
      user: rows[0],
      orders: orders
    });
  } catch (err) {
    console.error('Error obteniendo usuario:', err);
    res.status(500).json({ error: 'Error al obtener usuario' });
  }
});

// ✏️ ACTUALIZAR USUARIO (ADMIN)
app.put('/api/admin/users/:id', authMiddleware, adminOnly, async (req, res) => {
  const { nombre, apellidoP, apellidoM, telefono, usuario, rol, verificado } = req.body;

  if (!nombre || !apellidoP || !usuario) {
    return res.status(400).json({ error: 'Faltan campos requeridos' });
  }

  if (!validateUsername(usuario)) {
    return res.status(400).json({ error: 'Usuario inválido' });
  }

  // Validar rol
  if (rol && !['admin', 'cliente'].includes(rol)) {
    return res.status(400).json({ error: 'Rol inválido' });
  }

  const nombreSafe = sanitizeInput(nombre);
  const apellidoPSafe = sanitizeInput(apellidoP);
  const apellidoMSafe = apellidoM ? sanitizeInput(apellidoM) : null;
  const usuarioSafe = sanitizeInput(usuario);
  const telefonoSafe = telefono ? sanitizeInput(telefono) : null;

  try {
    const db = await getDB();

    // Verificar que el usuario existe
    const [exists] = await db.execute('SELECT id FROM users WHERE id = ?', [req.params.id]);
    
    if (exists.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    // Verificar duplicados
    const [duplicates] = await db.execute(`
      SELECT id FROM users 
      WHERE (usuario = ? OR telefono = ?) AND id != ?
    `, [usuarioSafe, telefonoSafe, req.params.id]);

    if (duplicates.length > 0) {
      return res.status(400).json({ error: 'Usuario o teléfono ya registrado' });
    }

    await db.execute(`
      UPDATE users 
      SET nombre=?, apellidoP=?, apellidoM=?, telefono=?, usuario=?, rol=?, verificado=?, updatedAt=NOW()
      WHERE id=?
    `, [nombreSafe, apellidoPSafe, apellidoMSafe, telefonoSafe, usuarioSafe, rol || 'cliente', verificado !== undefined ? verificado : 1, req.params.id]);

    console.log(`✅ Usuario actualizado: ${usuarioSafe} (ID: ${req.params.id}) por admin ${req.user.usuario}`);
    res.json({ message: 'Usuario actualizado correctamente' });
  } catch (err) {
    console.error('Error actualizando usuario:', err);
    res.status(500).json({ error: 'Error actualizando usuario' });
  }
});

// 🗑️ DESACTIVAR USUARIO
app.delete('/api/admin/users/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();

    // No permitir que un admin se elimine a sí mismo
    if (req.user.id === parseInt(req.params.id)) {
      return res.status(400).json({ error: 'No puedes eliminar tu propia cuenta' });
    }

    const [exists] = await db.execute('SELECT id, usuario FROM users WHERE id = ?', [req.params.id]);
    
    if (exists.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    // Desactivar cuenta
    await db.execute(`
      UPDATE users 
      SET verificado = 0, updatedAt = NOW()
      WHERE id = ?
    `, [req.params.id]);

    console.log(`⚠️ Usuario desactivado: ${exists[0].usuario} (ID: ${req.params.id}) por admin ${req.user.usuario}`);
    res.json({ message: 'Usuario desactivado correctamente' });
  } catch (err) {
    console.error('Error eliminando usuario:', err);
    res.status(500).json({ error: 'Error eliminando usuario' });
  }
});

// 🔓 DESBLOQUEAR USUARIO
app.patch('/api/admin/users/:id/unlock', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();

    const [exists] = await db.execute('SELECT id, usuario FROM users WHERE id = ?', [req.params.id]);
    
    if (exists.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    await db.execute(`
      UPDATE users 
      SET failedAttempts = 0, lockedUntil = NULL, updatedAt = NOW()
      WHERE id = ?
    `, [req.params.id]);

    console.log(`🔓 Usuario desbloqueado: ${exists[0].usuario} por admin ${req.user.usuario}`);
    res.json({ message: 'Usuario desbloqueado correctamente' });
  } catch (err) {
    console.error('Error desbloqueando usuario:', err);
    res.status(500).json({ error: 'Error desbloqueando usuario' });
  }
});

// 🔑 RESETEAR CONTRASEÑA DE USUARIO (ADMIN)
app.post('/api/admin/users/:id/reset-password', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();

    const [user] = await db.execute('SELECT id, usuario, correo, nombre FROM users WHERE id = ?', [req.params.id]);
    
    if (user.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    // Generar contraseña temporal
    const tempPassword = generarPasswordAleatoria(12);
    const hash = await bcrypt.hash(tempPassword, 12);

    await db.execute('UPDATE users SET password = ?, updatedAt = NOW() WHERE id = ?', [hash, req.params.id]);

    // Enviar correo con la nueva contraseña
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: process.env.EMAIL_PORT,
      secure: false,
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
    });

    await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: user[0].correo,
      subject: 'Contraseña restablecida - SportLike',
      html: `
        <p>Hola ${user[0].nombre},</p>
        <p>Tu contraseña ha sido restablecida por un administrador.</p>
        <p><strong>Tu nueva contraseña temporal es:</strong> ${tempPassword}</p>
        <p>Por seguridad, te recomendamos cambiarla al iniciar sesión.</p>
      `
    });

    console.log(`🔑 Contraseña reseteada para usuario: ${user[0].usuario} por admin ${req.user.usuario}`);
    res.json({ 
      message: 'Contraseña restablecida. Se ha enviado la nueva contraseña al correo del usuario.',
      tempPassword: tempPassword
    });
  } catch (err) {
    console.error('Error reseteando contraseña:', err);
    res.status(500).json({ error: 'Error reseteando contraseña' });
  }
});

// 📊 ESTADÍSTICAS DE USUARIOS
app.get('/api/admin/users/stats/summary', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();

    const [stats] = await db.execute(`
      SELECT 
        COUNT(*) AS total_usuarios,
        SUM(CASE WHEN rol = 'admin' THEN 1 ELSE 0 END) AS admins,
        SUM(CASE WHEN rol = 'cliente' THEN 1 ELSE 0 END) AS clientes,
        SUM(CASE WHEN verificado = 1 THEN 1 ELSE 0 END) AS verificados,
        SUM(CASE WHEN verificado = 0 THEN 1 ELSE 0 END) AS sin_verificar,
        SUM(CASE WHEN lockedUntil IS NOT NULL AND lockedUntil > NOW() THEN 1 ELSE 0 END) AS bloqueados
      FROM users
    `);

    const [registrosPorMes] = await db.execute(`
      SELECT 
        DATE_FORMAT(createdAt, '%Y-%m') AS mes,
        COUNT(*) AS registros
      FROM users
      WHERE createdAt >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
      GROUP BY mes
      ORDER BY mes
    `);

    res.json({
      resumen: stats[0],
      registrosPorMes: registrosPorMes
    });
  } catch (err) {
    console.error('Error obteniendo estadísticas de usuarios:', err);
    res.status(500).json({ error: 'Error obteniendo estadísticas' });
  }
});

// ================================
// 📦 ADMIN - ÓRDENES
// ================================

// 📋 OBTENER TODAS LAS ÓRDENES
app.get('/api/admin/orders', authMiddleware, adminOnly, async (req, res) => {
  const { estado, sucursal, from, to, user_id } = req.query;

  try {
    const db = await getDB();

    let sql = `
      SELECT 
        o.id,
        o.user_id,
        o.total,
        o.fecha,
        o.estado,
        o.sucursal,
        o.metodo_pago,
        o.direccion_envio,
        u.nombre,
        u.apellidoP,
        u.usuario,
        u.correo
      FROM orders o
      LEFT JOIN users u ON u.id = o.user_id
      WHERE 1=1
    `;

    const params = [];

    if (estado && estado !== 'all') {
      sql += " AND o.estado = ?";
      params.push(estado);
    }

    if (sucursal && sucursal !== 'all') {
      sql += " AND o.sucursal = ?";
      params.push(sucursal);
    }

    if (from) {
      sql += " AND o.fecha >= ?";
      params.push(from);
    }

    if (to) {
      sql += " AND o.fecha <= ?";
      params.push(to);
    }

    if (user_id) {
      sql += " AND o.user_id = ?";
      params.push(user_id);
    }

    sql += " ORDER BY o.fecha DESC";

    const [rows] = await db.execute(sql, params);
    res.json(rows);
  } catch (err) {
    console.error('Error obteniendo órdenes:', err);
    res.status(500).json({ error: 'Error obteniendo órdenes' });
  }
});

// 📄 OBTENER DETALLE DE UNA ORDEN
app.get('/api/admin/orders/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();

    const [order] = await db.execute(`
      SELECT 
        o.*,
        u.nombre,
        u.apellidoP,
        u.apellidoM,
        u.usuario,
        u.correo,
        u.telefono
      FROM orders o
      LEFT JOIN users u ON u.id = o.user_id
      WHERE o.id = ?
    `, [req.params.id]);

    if (order.length === 0) {
      return res.status(404).json({ error: 'Orden no encontrada' });
    }

    const [items] = await db.execute(`
      SELECT 
        oi.*,
        p.nombre,
        p.imagen,
        p.categoria
      FROM order_items oi
      JOIN products p ON p.id = oi.product_id
      WHERE oi.order_id = ?
    `, [req.params.id]);

    res.json({
      order: order[0],
      items: items
    });
  } catch (err) {
    console.error('Error obteniendo detalle de orden:', err);
    res.status(500).json({ error: 'Error obteniendo orden' });
  }
});

// ✏️ ACTUALIZAR ESTADO DE ORDEN
app.patch('/api/admin/orders/:id/status', authMiddleware, adminOnly, async (req, res) => {
  const { estado } = req.body;

  const estadosValidos = ['pendiente', 'procesando', 'enviado', 'entregado', 'cancelado'];

  if (!estado || !estadosValidos.includes(estado)) {
    return res.status(400).json({ error: 'Estado inválido' });
  }

  try {
    const db = await getDB();

    const [exists] = await db.execute('SELECT id FROM orders WHERE id = ?', [req.params.id]);
    
    if (exists.length === 0) {
      return res.status(404).json({ error: 'Orden no encontrada' });
    }

    await db.execute(`
      UPDATE orders 
      SET estado = ?, updatedAt = NOW()
      WHERE id = ?
    `, [estado, req.params.id]);

    console.log(`✅ Estado de orden actualizado: Orden #${req.params.id} a '${estado}' por admin ${req.user.usuario}`);
    res.json({ message: 'Estado actualizado correctamente' });
  } catch (err) {
    console.error('Error actualizando estado de orden:', err);
    res.status(500).json({ error: 'Error actualizando estado' });
  }
});

// 📊 ESTADÍSTICAS DE ÓRDENES
app.get('/api/admin/orders/stats/summary', authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();

    const [stats] = await db.execute(`
      SELECT 
        COUNT(*) AS total_ordenes,
        SUM(total) AS ingresos_totales,
        AVG(total) AS ticket_promedio,
        SUM(CASE WHEN estado = 'pendiente' THEN 1 ELSE 0 END) AS pendientes,
        SUM(CASE WHEN estado = 'procesando' THEN 1 ELSE 0 END) AS procesando,
        SUM(CASE WHEN estado = 'enviado' THEN 1 ELSE 0 END) AS enviado,
        SUM(CASE WHEN estado = 'entregado' THEN 1 ELSE 0 END) AS entregadas,
        SUM(CASE WHEN estado = 'cancelado' THEN 1 ELSE 0 END) AS canceladas
      FROM orders
    `);

    const [porSucursal] = await db.execute(`
      SELECT 
        sucursal,
        COUNT(*) AS ordenes,
        SUM(total) AS ingresos
      FROM orders
      GROUP BY sucursal
      ORDER BY ingresos DESC
    `);

    const [ventasPorDia] = await db.execute(`
      SELECT 
        DATE(fecha) AS dia,
        COUNT(*) AS ordenes,
        SUM(total) AS ingresos
      FROM orders
      WHERE fecha >= DATE_SUB(NOW(), INTERVAL 30 DAY)
      GROUP BY dia
      ORDER BY dia
    `);

    res.json({
      resumen: stats[0],
      porSucursal: porSucursal,
      ventasPorDia: ventasPorDia
    });
  } catch (err) {
    console.error('Error obteniendo estadísticas de órdenes:', err);
    res.status(500).json({ error: 'Error obteniendo estadísticas' });
  }
});

// ================================
// 🚀 START SERVER
// ================================

const PORT = process.env.PORT || 1234;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
  console.log(`🔒 Seguridad: Rate limiting activado`);
  console.log(`🛡️ Helmet protections activadas`);
  console.log(`📦 Endpoints de admin mejorados disponibles`);
});