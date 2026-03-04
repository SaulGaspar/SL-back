const express    = require('express');
const cors       = require('cors');
const bodyParser = require('body-parser');
const helmet     = require('helmet');
const passport   = require('passport');
require('dotenv').config();

const { loginLimiter, generalLimiter } = require('./middlewares/rateLimiter');

// ── Rutas públicas ──────────────────────────────────────────
const authRoutes     = require('./routes/public/auth.routes');
const passwordRoutes = require('./routes/public/password.routes');
const profileRoutes  = require('./routes/public/profile.routes');
const publicProducts = require('./routes/public/products.routes');

// ── Rutas admin ─────────────────────────────────────────────
const adminProducts  = require('./routes/admin/products.routes');
const adminInventory = require('./routes/admin/inventory.routes');
const adminBranches  = require('./routes/admin/branches.routes');
const adminUsers     = require('./routes/admin/users.routes');
const adminOrders    = require('./routes/admin/orders.routes');
const adminDashboard = require('./routes/admin/dashboard.routes');

const app = express();
app.set('trust proxy', 1);

// ================================
// 🛡️ SEGURIDAD
// ================================

app.use(helmet());

const allowedOrigins = [
  'https://sportlikeapps.netlify.app',
  'http://localhost:1234',
  'https://sl-back.vercel.app'
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('CORS no permitido'));
  },
  credentials: true
}));

// ================================
// 🔐 JWT SECRET VALIDATION
// ================================

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET || JWT_SECRET === 'change_this_secret') {
  console.error('❌ ERROR: JWT_SECRET no configurado o usando valor por defecto inseguro');
  process.exit(1);
}

// ================================
// ⚙️ MIDDLEWARES GENERALES
// ================================

app.use(bodyParser.json({ limit: '10mb' }));
app.use(passport.initialize());

app.use('/api/login', loginLimiter);
app.use('/api/', generalLimiter);

// ================================
// 📍 HEALTH CHECK
// ================================

app.get('/', (req, res) => res.send('Servidor SportLike funcionando correctamente'));

// ================================
// 🔀 RUTAS PÚBLICAS
// ================================

app.use('/auth', authRoutes);              // /auth/google, /auth/google/callback
app.use('/api',  authRoutes);              // /api/register, /api/login, /api/verify-email
app.use('/api',  passwordRoutes);          // /api/forgot-password, /api/reset-password
app.use('/api',  profileRoutes);           // /api/me, /api/update-profile, /api/update-password
app.use('/api/products', publicProducts);  // /api/products, /api/products/categories, /api/products/marcas

// ================================
// 🔀 RUTAS ADMIN
// ================================

app.use('/api/admin/products',  adminProducts);   // /api/admin/products + CRUD completo
app.use('/api/admin/inventory', adminInventory);  // /api/admin/inventory + transferencias
app.use('/api/admin/branches',  adminBranches);   // /api/admin/branches
app.use('/api/admin/users',     adminUsers);      // /api/admin/users
app.use('/api/admin/orders',    adminOrders);     // /api/admin/orders
app.use('/api/admin/dashboard', adminDashboard);  // /api/admin/dashboard

module.exports = app;
