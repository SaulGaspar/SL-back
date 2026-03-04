const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const { getDB } = require('../../config/db');
const { createTransporter } = require('../../helpers/mailer');
const {
  sanitizeInput,
  validateEmail,
  validatePassword,
  validateUsername,
  generarPasswordAleatoria
} = require('../../helpers/validators');

const JWT_SECRET = process.env.JWT_SECRET;

// ================================
// 🔐 GOOGLE OAUTH - STRATEGY
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

      if (!validateEmail(correo)) return done(new Error('Email inválido'), null);

      const [rows] = await db.execute('SELECT * FROM users WHERE correo = ?', [correo]);
      let user;

      if (rows.length > 0) {
        user = rows[0];
      } else {
        const tempPassword = generarPasswordAleatoria();
        const hash = await bcrypt.hash(tempPassword, 10);

        const nombreCompleto = profile.displayName || 'Usuario';
        const partesNombre = nombreCompleto.trim().split(' ');

        const nombre    = sanitizeInput(partesNombre[0] || 'Usuario');
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

        user = { id: result.insertId, nombre, apellidoP, apellidoM, correo, usuario, rol: 'cliente' };
      }

      // Nunca permitir rol admin por OAuth
      if (user.rol === 'admin') user.rol = 'cliente';

      const token = jwt.sign(
        {
          id: user.id, usuario: user.usuario, rol: user.rol,
          correo: user.correo, nombre: user.nombre,
          apellidoP: user.apellidoP, apellidoM: user.apellidoM
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

// GET /auth/google
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// GET /auth/google/callback
router.get('/google/callback', passport.authenticate('google', { session: false }), (req, res) => {
  res.redirect(`${process.env.CLIENT_URL}/google-callback?token=${req.user}`);
});

// ================================
// POST /api/register
// ================================

router.post('/register', async (req, res) => {
  const { nombre, apellidoP, apellidoM, fechaNac, correo, telefono, usuario, password } = req.body;

  if (!nombre || !apellidoP || !usuario || !correo || !password)
    return res.status(400).json({ error: 'Faltan campos requeridos' });
  if (!validateEmail(correo))
    return res.status(400).json({ error: 'Email inválido' });
  if (!validateUsername(usuario))
    return res.status(400).json({ error: 'Usuario inválido. Debe tener 4-20 caracteres alfanuméricos' });
  if (!validatePassword(password))
    return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula, un número y un carácter especial' });

  const nombreSafe    = sanitizeInput(nombre);
  const apellidoPSafe = sanitizeInput(apellidoP);
  const apellidoMSafe = apellidoM ? sanitizeInput(apellidoM) : null;
  const usuarioSafe   = sanitizeInput(usuario);
  const correoSafe    = sanitizeInput(correo);
  const telefonoSafe  = telefono ? sanitizeInput(telefono) : null;

  try {
    const db = await getDB();

    const [existing] = await db.execute(
      'SELECT id FROM users WHERE usuario = ? OR correo = ? OR telefono = ?',
      [usuarioSafe, correoSafe, telefonoSafe]
    );
    if (existing.length > 0)
      return res.status(400).json({ error: 'Usuario, correo o teléfono ya registrado' });

    const hash = await bcrypt.hash(password, 12);

    const [result] = await db.execute(
      `INSERT INTO users (nombre, apellidoP, apellidoM, fechaNac, correo, telefono, usuario, password, rol, verificado, createdAt, updatedAt)
       VALUES (?,?,?,?,?,?,?,?,?,0,NOW(),NOW())`,
      [nombreSafe, apellidoPSafe, apellidoMSafe, fechaNac || null, correoSafe, telefonoSafe, usuarioSafe, hash, 'cliente']
    );

    const token = jwt.sign({ id: result.insertId, correo: correoSafe }, JWT_SECRET, { expiresIn: '1d' });
    const verifyLink = `${process.env.CLIENT_URL}/verify-email?token=${token}`;

    const transporter = createTransporter();
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
// POST /api/login
// ================================

router.post('/login', async (req, res) => {
  const { usuario, password } = req.body;

  if (!usuario || !password)
    return res.status(400).json({ error: 'Usuario y contraseña requeridos' });

  const usuarioSafe = sanitizeInput(usuario);

  try {
    const db = await getDB();

    const [rows] = await db.execute(
      'SELECT id, nombre, apellidoP, apellidoM, usuario, correo, password, rol, verificado, failedAttempts, lockedUntil FROM users WHERE usuario = ?',
      [usuarioSafe]
    );

    if (rows.length === 0) return res.status(401).json({ error: 'Credenciales incorrectas' });

    const user = rows[0];

    if (user.lockedUntil && new Date(user.lockedUntil) > new Date()) {
      const minutos = Math.ceil((new Date(user.lockedUntil) - new Date()) / 60000);
      return res.status(403).json({ error: `Cuenta bloqueada. Intenta en ${minutos} minutos.` });
    }

    if (user.verificado === 0)
      return res.status(403).json({ error: 'Debes verificar tu correo antes de iniciar sesión' });

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      const intentos = user.failedAttempts + 1;
      let lock = null;

      if (intentos >= 3) {
        lock = new Date(Date.now() + 30 * 60 * 1000);
        console.warn(`⚠️ Cuenta bloqueada: ${user.usuario}`);
      }

      await db.execute('UPDATE users SET failedAttempts=?, lockedUntil=? WHERE id=?', [intentos, lock, user.id]);

      if (intentos >= 3)
        return res.status(403).json({ error: 'Cuenta bloqueada por 30 minutos debido a múltiples intentos fallidos' });

      return res.status(401).json({ error: `Credenciales incorrectas. Intentos restantes: ${3 - intentos}` });
    }

    await db.execute('UPDATE users SET failedAttempts=0, lockedUntil=NULL WHERE id=?', [user.id]);

    const jwtToken = jwt.sign(
      { id: user.id, usuario: user.usuario, rol: user.rol, correo: user.correo, nombre: user.nombre },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    console.log(`✅ Login exitoso: ${user.usuario} (${user.rol})`);

    res.json({
      user: {
        id: user.id, nombre: user.nombre, apellidoP: user.apellidoP,
        apellidoM: user.apellidoM, usuario: user.usuario, rol: user.rol, correo: user.correo
      },
      token: jwtToken
    });

  } catch (err) {
    console.error('Error en login:', err);
    res.status(500).json({ error: 'Error en login' });
  }
});

// ================================
// GET /api/verify-email
// ================================

router.get('/verify-email', async (req, res) => {
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

module.exports = router;
