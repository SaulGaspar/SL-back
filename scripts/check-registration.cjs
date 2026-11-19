const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const express = require('express');

process.env.JWT_SECRET = 'qa-registration-secret';
process.env.CLIENT_URL = 'https://sportlike.example.test';
process.env.GOOGLE_CLIENT_ID = 'qa-client';
process.env.GOOGLE_CLIENT_SECRET = 'qa-secret';
process.env.GOOGLE_CALLBACK_URL = 'https://sportlike.example.test/auth/google/callback';
process.env.EMAIL_FROM = 'qa@sportlike.example.test';

const dbPath = path.resolve(__dirname, '../config/db.js');
const mailPath = path.resolve(__dirname, '../helpers/mailer.js');

let mode = 'success';
let databaseCalls = 0;
let committed = 0;
let rolledBack = 0;
let released = 0;
let sentEmails = 0;
let insertedValues;

const connection = {
  async beginTransaction() {},
  async execute(sql, values) {
    databaseCalls += 1;
    if (sql.startsWith('SELECT id FROM users')) {
      return [mode === 'duplicate' ? [{ id: 7 }] : []];
    }
    if (sql.startsWith('INSERT INTO users')) {
      insertedValues = values;
      return [{ insertId: 21 }];
    }
    throw new Error(`SQL inesperado: ${sql}`);
  },
  async commit() { committed += 1; },
  async rollback() { rolledBack += 1; },
  release() { released += 1; },
};

require.cache[dbPath] = {
  id: dbPath,
  filename: dbPath,
  loaded: true,
  exports: { getDB: async () => ({ getConnection: async () => connection }) },
};
require.cache[mailPath] = {
  id: mailPath,
  filename: mailPath,
  loaded: true,
  exports: {
    createTransporter: () => ({
      async sendMail() {
        sentEmails += 1;
        if (mode === 'mailer-error') throw new Error('SMTP no disponible');
      },
    }),
  },
};

const app = express();
app.use(express.json());
app.use('/auth', require('../routes/public/auth.routes'));

const server = http.createServer(app);

async function post(base, body) {
  return fetch(`${base}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

async function main() {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const valid = {
    nombre: 'Saúl',
    apellidoPaterno: 'Gaspar',
    apellidoMaterno: 'Pérez',
    fechaNacimiento: '2000-10-10',
    correo: ' SAUL@EXAMPLE.TEST ',
    telefono: '771 123 4567',
    usuario: 'saul_g',
    password: 'Segura123!',
  };

  try {
    const missing = await post(base, { nombre: 'Saúl' });
    assert.equal(missing.status, 400);
    assert.match((await missing.json()).error, /apellido paterno.*fecha de nacimiento.*correo electrónico/);
    assert.equal(databaseCalls, 0);

    const invalidDate = await post(base, { ...valid, fechaNacimiento: '2000-02-31' });
    assert.equal(invalidDate.status, 400);
    assert.equal(databaseCalls, 0);

    mode = 'success';
    const success = await post(base, valid);
    assert.equal(success.status, 201);
    assert.equal((await success.json()).message, 'Cuenta creada correctamente. Revisa tu correo para activarla.');
    assert.equal(insertedValues[1], 'Gaspar');
    assert.equal(insertedValues[3], '2000-10-10');
    assert.equal(insertedValues[4], 'saul@example.test');
    assert.equal(insertedValues[5], '7711234567');
    assert.equal(committed, 1);
    assert.equal(sentEmails, 1);

    mode = 'duplicate';
    const duplicate = await post(base, valid);
    assert.equal(duplicate.status, 409);
    assert.match((await duplicate.json()).error, /ya está registrado/);

    mode = 'mailer-error';
    const mailFailure = await post(base, { ...valid, correo: 'otro@example.test', usuario: 'otro_user' });
    assert.equal(mailFailure.status, 500);
    assert.match((await mailFailure.json()).error, /No pudimos crear tu cuenta/);
    assert.ok(rolledBack >= 2);
    assert.equal(released, 3);

    console.log('REGISTRO OK: contrato móvil, validaciones, duplicados y rollback si falla el correo. Sin BD ni correos reales.');
  } finally {
    server.close();
  }
}

main().catch((error) => {
  console.error(error);
  server.close();
  process.exitCode = 1;
});
