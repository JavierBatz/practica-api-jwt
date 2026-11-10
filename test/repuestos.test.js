const request = require('supertest');
const jwt = require('jsonwebtoken');
const sql = require('mssql');
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');

const { app, poolPromise } = require('../server');

const issuer = 'practica-api-jwt';
const audience = 'practica-repuestos';

let tokenUsuario;
let tokenAdmin;
let pool;

function generarToken(id, rol) {
  return jwt.sign({ rol }, process.env.JWT_SECRET, {
    algorithm: 'HS256',
    subject: String(id),
    issuer,
    audience,
    expiresIn: '15m'
  });
}

before(async () => {
  pool = await poolPromise;

  const usuarios = await pool.request().query(`
    SELECT UsuarioId, Email
    FROM dbo.Usuarios
    WHERE Email IN (
      'testusuario@ejemplo.com',
      'testadmin@ejemplo.com'
    )
  `);

  const usuario = usuarios.recordset.find(
    u => u.Email === 'testusuario@ejemplo.com'
  );

  const admin = usuarios.recordset.find(
    u => u.Email === 'testadmin@ejemplo.com'
  );

  if (!usuario || !admin) {
    throw new Error('Faltan usuarios de prueba en SQL Server');
  }

  tokenUsuario = generarToken(usuario.UsuarioId, 'usuario');
  tokenAdmin = generarToken(admin.UsuarioId, 'admin');

  await pool.request()
    .input('codigo', sql.VarChar(30), 'TEST-JEST-001')
    .query('DELETE FROM dbo.Repuestos WHERE Codigo = @codigo');
});

after(async () => {
  if (pool) {
    await pool.request()
      .input('codigo', sql.VarChar(30), 'TEST-JEST-001')
      .query('DELETE FROM dbo.Repuestos WHERE Codigo = @codigo');

    await pool.close();
  }
});

test('401 - sin token', async () => {
  const response = await request(app)
    .post('/api/repuestos')
    .send({
      codigo: 'TEST-JEST-001',
      nombre: 'Filtro de prueba',
      precio: 50,
      stock: 10
    });

  assert.equal(response.status, 401);
});

test('403 - usuario normal', async () => {
  const response = await request(app)
    .post('/api/repuestos')
    .set('Authorization', `Bearer ${tokenUsuario}`)
    .send({
      codigo: 'TEST-JEST-001',
      nombre: 'Filtro de prueba',
      precio: 50,
      stock: 10
    });

  assert.equal(response.status, 403);
});

test('201 - administrador', async () => {
  const response = await request(app)
    .post('/api/repuestos')
    .set('Authorization', `Bearer ${tokenAdmin}`)
    .send({
      codigo: 'TEST-JEST-001',
      nombre: 'Filtro de prueba',
      precio: 50,
      stock: 10
    });

  assert.equal(response.status, 201);
  assert.ok(response.body.dato.RepuestoId);
  assert.equal(response.body.dato.Codigo, 'TEST-JEST-001');
});
