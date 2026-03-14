
const sanitizeLog = (value) =>
  String(value ?? '').replace(/[\r\n\t\x00-\x1f\x7f]/g, ' ').trim();

module.exports = { sanitizeLog };
