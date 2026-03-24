require('dotenv').config();
const app = require('./app');
const { iniciarScheduler } = require('./config/scheduler');

// ================================
// 🚀 START SERVER
// ================================

const PORT = process.env.PORT || 1234;

app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
  iniciarScheduler();
});

module.exports = app;