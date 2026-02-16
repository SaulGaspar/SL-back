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
// 👥 ADMIN - USUARIOS
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
// 🛍️ ADMIN - PRODUCTOS
// ================================

app.get("/api/admin/products", authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.execute(`
      SELECT id, nombre, descripcion, precio, categoria, imagen, activo
      FROM products
      ORDER BY id DESC
    `);
    res.json(rows);
  } catch (err) {
    console.error('Error obteniendo productos:', err);
    res.status(500).json({ error: "Error obteniendo productos" });
  }
});

app.post("/api/admin/products", authMiddleware, adminOnly, async (req, res) => {
  const { nombre, descripcion, precio, categoria, imagen } = req.body;

  if (!nombre || !precio) {
    return res.status(400).json({ error: "Nombre y precio obligatorios" });
  }

  const nombreSafe = sanitizeInput(nombre);
  const descripcionSafe = descripcion ? sanitizeInput(descripcion) : null;
  const categoriaSafe = categoria ? sanitizeInput(categoria) : null;

  try {
    const db = await getDB();
    await db.execute(`
      INSERT INTO products
      (nombre, descripcion, precio, categoria, imagen, activo)
      VALUES (?,?,?,?,?,1)
    `, [nombreSafe, descripcionSafe, precio, categoriaSafe, imagen]);

    res.json({ message: "Producto creado correctamente" });
  } catch (err) {
    console.error('Error creando producto:', err);
    res.status(500).json({ error: "Error creando producto" });
  }
});

app.put("/api/admin/products/:id", authMiddleware, adminOnly, async (req, res) => {
  const { nombre, descripcion, precio, categoria, imagen, activo } = req.body;

  const nombreSafe = sanitizeInput(nombre);
  const descripcionSafe = descripcion ? sanitizeInput(descripcion) : null;
  const categoriaSafe = categoria ? sanitizeInput(categoria) : null;

  try {
    const db = await getDB();
    await db.execute(`
      UPDATE products
      SET nombre=?, descripcion=?, precio=?, categoria=?, imagen=?, activo=?, updatedAt=NOW()
      WHERE id=?
    `, [nombreSafe, descripcionSafe, precio, categoriaSafe, imagen, activo, req.params.id]);

    res.json({ message: "Producto actualizado" });
  } catch (err) {
    console.error('Error actualizando producto:', err);
    res.status(500).json({ error: "Error actualizando producto" });
  }
});

app.delete("/api/admin/products/:id", authMiddleware, adminOnly, async (req, res) => {
  try {
    const db = await getDB();
    await db.execute(`
      UPDATE products
      SET activo = 0
      WHERE id = ?
    `, [req.params.id]);

    res.json({ message: "Producto desactivado" });
  } catch (err) {
    console.error('Error eliminando producto:', err);
    res.status(500).json({ error: "Error eliminando producto" });
  }
});

// ================================
// 📦 ADMIN - INVENTARIO
// ================================

app.get("/api/admin/inventory", authMiddleware, adminOnly, async (req, res) => {
  const { branch } = req.query;

  try {
    const db = await getDB();

    let sql = `
      SELECT 
        i.id,
        b.nombre AS sucursal,
        p.nombre AS producto,
        i.stock,
        i.min_stock,
        i.branch_id,
        i.product_id
      FROM inventory i
      JOIN products p ON p.id = i.product_id
      JOIN branches b ON b.id = i.branch_id
    `;

    let params = [];

    if (branch) {
      sql += " WHERE i.branch_id = ?";
      params.push(branch);
    }

    const [rows] = await db.execute(sql, params);
    res.json(rows);
  } catch (err) {
    console.error('Error obteniendo inventario:', err);
    res.status(500).json({ error: "Error obteniendo inventario" });
  }
});

app.put("/api/admin/inventory/:id", authMiddleware, adminOnly, async (req, res) => {
  const { stock, min_stock } = req.body;

  try {
    const db = await getDB();
    await db.execute(`
      UPDATE inventory
      SET stock=?, min_stock=?
      WHERE id=?
    `, [stock, min_stock, req.params.id]);

    res.json({ message: "Inventario actualizado" });
  } catch (err) {
    console.error('Error actualizando inventario:', err);
    res.status(500).json({ error: "Error actualizando inventario" });
  }
});

// ================================
// 🚀 START SERVER
// ================================

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
  console.log(`🔒 Seguridad: Rate limiting activado`);
  console.log(`🛡️ Helmet protections activadas`);
});