// ================================
// 🔒 VALIDACIONES Y SANITIZACIÓN
// ================================

function sanitizeInput(input) {
  if (typeof input !== 'string') return input;
  return input.trim().replace(/['"`;\\]/g, '');
}

function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

function validatePassword(password) {
  const re = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  return re.test(password);
}

function validateUsername(usuario) {
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

module.exports = {
  sanitizeInput,
  validateEmail,
  validatePassword,
  validateUsername,
  generarPasswordAleatoria
};
