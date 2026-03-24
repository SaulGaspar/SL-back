require('dotenv').config();
const app = require('./app');

// ================================
// 🚀 START SERVER
// ================================

const PORT = process.env.PORT || 1234;

app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
});

module.exports = app;