const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const {googleSession,googleRegistration,readRegistration,beginGoogle,finishGoogleState} = require('../../helpers/googleAuth');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const { getDB } = require('../../config/db');
const { createTransporter } = require('../../helpers/mailer');
const {
  sanitizeInput,
  validateEmail,
  validatePassword,
  validateUsername
} = require('../../helpers/validators');

const JWT_SECRET = process.env.JWT_SECRET;


passport.use(new GoogleStrategy(
  {
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL
  },
  async (_accessToken, _refreshToken, profile, done) => {
    try {
      const email = profile.emails?.[0];
      const correo = String(email?.value || '').trim().toLowerCase();
      const verified = email?.verified === true || profile._json?.email_verified === true || profile._json?.verified_email === true;
      if (!validateEmail(correo) || !verified) return done(null,false,{message:'Google no pudo verificar este correo.'});
      const db = await getDB();
      const [rows] = await db.execute('SELECT * FROM users WHERE correo = ?', [correo]);
      if (rows.length) {
        const user = rows[0];
        if (user.lockedUntil && new Date(user.lockedUntil) > new Date()) return done(null,false,{message:'La cuenta está bloqueada temporalmente. Intenta más tarde.'});
        return done(null,googleSession(user));
      }
      // El registro todavía no escribe en la BD ni crea una sesión.
      return done(null,{registration_token:googleRegistration(profile,correo)});
    } catch (error) {
      console.error('Error en Google OAuth:', error.message);
      done(error,null);
    }
  }
));

router.use('/google',(_req,res,next)=>{res.set('Cache-Control','no-store');res.set('Referrer-Policy','no-referrer');next();});

router.get('/google',(req,res,next)=>{
  try {
    const state = beginGoogle(req,res);
    passport.authenticate('google',{scope:['profile','email'],state})(req,res,next);
  } catch { res.status(400).json({error:'No se pudo iniciar el acceso con Google.'}); }
});

router.get('/google/callback',(req,res,next)=>{
  let origin;
  try { origin = finishGoogleState(req,res); }
  catch { return res.status(400).send('El acceso con Google expiró o no corresponde a este navegador. Vuelve a iniciar sesión.'); }
  passport.authenticate('google',{session:false},(error,result)=>{
    const destination = new URL('/google-callback',origin);
    if (error || !result) destination.hash = new URLSearchParams({error:'google_access_failed'}).toString();
    else destination.hash = new URLSearchParams(result.registration_token ? {registration_token:result.registration_token} : {token:result.token}).toString();
    res.redirect(destination.toString());
  })(req,res,next);
});

router.get('/google/registration',(req,res)=>{
  try {
    const data = readRegistration(req);
    res.json({correo:data.correo,nombre:data.nombre});
  } catch { res.status(401).json({error:'El registro expiró. Vuelve a continuar con Google.'}); }
});

router.post('/google/complete',async(req,res)=>{
  let registration;
  try { registration=readRegistration(req); }
  catch { return res.status(401).json({error:'El registro expiró. Vuelve a continuar con Google.'}); }
  const usuario = typeof req.body?.usuario === 'string' ? req.body.usuario.trim() : '';
  if (!validateUsername(usuario)) return res.status(400).json({error:'Elige un usuario de 4 a 20 caracteres: letras, números, guion o guion bajo.'});
  try {
    const db = await getDB();
    const [existing] = await db.execute('SELECT * FROM users WHERE correo = ?',[registration.correo]);
    // Permite reintentar si la primera respuesta se perdió, sin duplicar ni cambiar la cuenta.
    if (existing.length) return res.json(googleSession(existing[0]));
    const [taken] = await db.execute('SELECT id FROM users WHERE usuario = ?',[usuario]);
    if (taken.length) return res.status(409).json({error:'Ese nombre de usuario ya está ocupado. Elige otro.'});
    const hash = await bcrypt.hash(crypto.randomBytes(48).toString('base64url'),12);
    const [result] = await db.execute(
      `INSERT INTO users (nombre,apellidoP,apellidoM,correo,usuario,password,rol,verificado,createdAt,updatedAt)
       VALUES (?,?,?,?,?,?,?,1,NOW(),NOW())`,
      [sanitizeInput(registration.nombre),sanitizeInput(registration.apellidoP),sanitizeInput(registration.apellidoM),registration.correo,usuario,hash,'cliente']
    );
    const [created] = await db.execute('SELECT * FROM users WHERE id = ?',[result.insertId]);
    res.status(201).json(googleSession(created[0]));
  } catch(error) {
    if (error.code === 'ER_DUP_ENTRY') return res.status(409).json({error:'El usuario o el correo ya está registrado. Intenta iniciar sesión otra vez.'});
    console.error('Error completando registro Google:',error.message);
    res.status(500).json({error:'No se pudo crear tu cuenta. Inténtalo nuevamente.'});
  }
});



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



router.post('/login', async (req, res) => {
  const { correo, password } = req.body || {};

  if (typeof correo !== 'string' || typeof password !== 'string' || !correo.trim() || !password)
    return res.status(400).json({ error: 'Correo y contraseña requeridos' });

  const correoSafe = correo.trim().toLowerCase();
  if (correoSafe.length > 254 || !validateEmail(correoSafe))
    return res.status(400).json({ error: 'Escribe un correo electrónico válido' });

  try {
    const db = await getDB();

    const [rows] = await db.execute(
      'SELECT id, nombre, apellidoP, apellidoM, usuario, correo, password, rol, verificado, failedAttempts, lockedUntil FROM users WHERE correo = ?',
      [correoSafe]
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
      const intentos = Number(user.failedAttempts || 0) + 1;
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
