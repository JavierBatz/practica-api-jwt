require('dotenv').config();
const express = require('express');
const sql = require('mssql');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');

const required = ['DB_SERVER', 'DB_NAME', 'DB_USER', 'DB_PASSWORD', 'JWT_SECRET'];
for (const key of required) {
  if (!process.env[key]) throw new Error(`Falta la variable ${key} en .env`);
}
if (Buffer.byteLength(process.env.JWT_SECRET, 'utf8') < 32) {
  throw new Error('JWT_SECRET debe tener al menos 32 bytes aleatorios');
}

const app = express();
app.use(helmet());
app.use(express.json({ limit: '20kb' }));
const dbConfig = {
  server: process.env.DB_SERVER,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  port: Number(process.env.DB_PORT || 1433),
  options: { encrypt: process.env.DB_ENCRYPT === 'true', trustServerCertificate: process.env.DB_TRUST_CERT === 'true' },
  pool: { max: 10, min: 0, idleTimeoutMillis: 30000 }
};
const poolPromise = new sql.ConnectionPool(dbConfig).connect();
const issuer = 'practica-api-jwt';
const audience = 'practica-repuestos';
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: 'draft-8', legacyHeaders: false });
const emailValido = s => typeof s === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s) && s.length <= 150;
const idValido = id => Number.isSafeInteger(Number(id)) && Number(id) > 0;
const noVacio = (s, max) => typeof s === 'string' && s.trim().length > 0 && s.trim().length <= max;
const valoresRepuestoValidos = b => b && noVacio(b.codigo, 30) && noVacio(b.nombre, 120) &&
  typeof b.precio === 'number' && Number.isFinite(b.precio) && b.precio >= 0 && b.precio <= 9999999999.99 &&
  Math.round(b.precio * 100) === b.precio * 100 && Number.isSafeInteger(b.stock) && b.stock >= 0;

app.get('/api/health', (_req, res) => res.json({ ok: true, servicio: 'API Repuestos' }));

app.post('/api/auth/register', authLimiter, async (req, res, next) => {
  try {
    const { nombre, email, password } = req.body || {};
    if (!noVacio(nombre, 100) || !emailValido(email) || typeof password !== 'string' || password.length < 10 || password.length > 72) {
      return res.status(400).json({ error: 'Nombre, email o contraseña inválidos (contraseña: 10 a 72 caracteres)' });
    }
    const hash = await bcrypt.hash(password, 12);
    const pool = await poolPromise;
    const result = await pool.request()
      .input('nombre', sql.NVarChar(100), nombre.trim())
      .input('email', sql.NVarChar(150), email.trim().toLowerCase())
      .input('hash', sql.NVarChar(255), hash)
      .query(`INSERT INTO dbo.Usuarios (Nombre, Email, PasswordHash)
              OUTPUT INSERTED.UsuarioId, INSERTED.Nombre, INSERTED.Email, INSERTED.Rol
              VALUES (@nombre, @email, @hash)`);
    return res.status(201).json({ usuario: result.recordset[0] });
  } catch (err) {
    if ([2601, 2627].includes(err.number)) return res.status(409).json({ error: 'El correo ya está registrado' });
    next(err);
  }
});

app.post('/api/auth/login', authLimiter, async (req, res, next) => {
  try {
    const { email, password } = req.body || {};
    if (!emailValido(email) || typeof password !== 'string') return res.status(400).json({ error: 'Credenciales inválidas' });
    const pool = await poolPromise;
    const result = await pool.request()
      .input('email', sql.NVarChar(150), email.trim().toLowerCase())
      .query(`SELECT UsuarioId, Nombre, Email, PasswordHash, Rol, Activo
              FROM dbo.Usuarios WHERE Email = @email`);
    const user = result.recordset[0];
    if (!user || !user.Activo || !(await bcrypt.compare(password, user.PasswordHash))) {
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }
    const token = jwt.sign({ rol: user.Rol }, process.env.JWT_SECRET, {
      algorithm: 'HS256', subject: String(user.UsuarioId), issuer, audience, expiresIn: '15m'
    });
    await pool.request().input('id', sql.Int, user.UsuarioId)
      .query('UPDATE dbo.Usuarios SET UltimoLogin = SYSUTCDATETIME() WHERE UsuarioId = @id');
    return res.json({ accessToken: token, tokenType: 'Bearer', expiresInSeconds: 900,
      usuario: { id: user.UsuarioId, nombre: user.Nombre, email: user.Email, rol: user.Rol } });
  } catch (err) { next(err); }
});

async function autenticar(req, res, next) {
  const authorization = req.headers.authorization;
  if (!authorization || !/^Bearer\s+\S+$/i.test(authorization)) {
    return res.status(401).json({ error: 'Falta Authorization: Bearer <token>' });
  }
  const token = authorization.split(/\s+/)[1];
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'], issuer, audience });
    if (!idValido(payload.sub)) return res.status(401).json({ error: 'Token inválido' });
    const pool = await poolPromise;
    const result = await pool.request().input('id', sql.Int, Number(payload.sub))
      .query('SELECT UsuarioId, Nombre, Email, Rol, Activo FROM dbo.Usuarios WHERE UsuarioId = @id');
    const usuario = result.recordset[0];
    if (!usuario || !usuario.Activo) return res.status(401).json({ error: 'Usuario no disponible' });
    req.usuario = { id: usuario.UsuarioId, nombre: usuario.Nombre, rol: usuario.Rol };
    return next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') return res.status(401).json({ error: 'Token expirado' });
    if (err.name === 'JsonWebTokenError' || err.name === 'NotBeforeError') return res.status(401).json({ error: 'Token inválido' });
    return next(err);
  }
}
function soloAdmin(req, res, next) {
  if (req.usuario.rol !== 'admin') return res.status(403).json({ error: 'No tienes permisos de administrador' });
  next();
}
app.get('/api/auth/me', autenticar, (req, res) => res.json({ usuario: req.usuario }));

app.get('/api/repuestos', autenticar, async (_req, res, next) => {
  try {
    const pool = await poolPromise;
    const result = await pool.request().query('SELECT RepuestoId, Codigo, Nombre, Precio, Stock FROM dbo.Repuestos WHERE Activo = 1 ORDER BY RepuestoId');
    res.json({ datos: result.recordset });
  } catch (err) { next(err); }
});
app.get('/api/repuestos/:id', autenticar, async (req, res, next) => {
  if (!idValido(req.params.id)) return res.status(400).json({ error: 'ID inválido' });
  try {
    const pool = await poolPromise;
    const result = await pool.request().input('id', sql.Int, Number(req.params.id))
      .query('SELECT RepuestoId, Codigo, Nombre, Precio, Stock FROM dbo.Repuestos WHERE RepuestoId = @id AND Activo = 1');
    if (!result.recordset[0]) return res.status(404).json({ error: 'Repuesto no encontrado' });
    res.json({ dato: result.recordset[0] });
  } catch (err) { next(err); }
});
app.post('/api/repuestos', autenticar, soloAdmin, async (req, res, next) => {
  if (!valoresRepuestoValidos(req.body)) return res.status(400).json({ error: 'Datos de repuesto inválidos' });
  try {
    const { codigo, nombre, precio, stock } = req.body;
    const pool = await poolPromise;
    const result = await pool.request()
      .input('codigo', sql.VarChar(30), codigo.trim()).input('nombre', sql.NVarChar(120), nombre.trim())
      .input('precio', sql.Decimal(12, 2), precio).input('stock', sql.Int, stock)
      .query(`INSERT dbo.Repuestos(Codigo, Nombre, Precio, Stock)
              OUTPUT INSERTED.RepuestoId, INSERTED.Codigo, INSERTED.Nombre, INSERTED.Precio, INSERTED.Stock
              VALUES (@codigo, @nombre, @precio, @stock)`);
    res.status(201).json({ dato: result.recordset[0] });
  } catch (err) {
    if ([2601, 2627].includes(err.number)) return res.status(409).json({ error: 'Código ya registrado' });
    next(err);
  }
});
app.patch('/api/repuestos/:id', autenticar, soloAdmin, async (req, res, next) => {
  if (!idValido(req.params.id)) return res.status(400).json({ error: 'ID inválido' });
  const { precio, stock } = req.body || {};
  if (!Number.isFinite(precio) || typeof precio !== 'number' || precio < 0 || precio > 9999999999.99 ||
      Math.round(precio * 100) !== precio * 100 || !Number.isSafeInteger(stock) || stock < 0) {
    return res.status(400).json({ error: 'Envía precio válido (2 decimales) y stock entero >= 0' });
  }
  try {
    const pool = await poolPromise;
    const result = await pool.request().input('id', sql.Int, Number(req.params.id))
      .input('precio', sql.Decimal(12, 2), precio).input('stock', sql.Int, stock)
      .query(`UPDATE dbo.Repuestos SET Precio = @precio, Stock = @stock
              OUTPUT INSERTED.RepuestoId, INSERTED.Codigo, INSERTED.Nombre, INSERTED.Precio, INSERTED.Stock
              WHERE RepuestoId = @id AND Activo = 1`);
    if (!result.recordset[0]) return res.status(404).json({ error: 'Repuesto no encontrado' });
    res.json({ dato: result.recordset[0] });
  } catch (err) { next(err); }
});
app.delete('/api/repuestos/:id', autenticar, soloAdmin, async (req, res, next) => {
  if (!idValido(req.params.id)) return res.status(400).json({ error: 'ID inválido' });
  try {
    const pool = await poolPromise;
    const result = await pool.request().input('id', sql.Int, Number(req.params.id))
      .query('UPDATE dbo.Repuestos SET Activo = 0 WHERE RepuestoId = @id AND Activo = 1');
    if (!result.rowsAffected[0]) return res.status(404).json({ error: 'Repuesto no encontrado' });
    res.status(204).send();
  } catch (err) { next(err); }
});
app.use((req, res) => res.status(404).json({ error: 'Ruta inexistente' }));
app.use((err, req, res, next) => {
  console.error('Error interno:', err);
  res.status(500).json({ error: 'Error interno del servidor' });
});
const port = Number(process.env.PORT || 3000);
poolPromise.then(() => app.listen(port, () => console.log(`API lista: http://localhost:${port}`)))
  .catch(err => { console.error('No fue posible conectar a SQL Server:', err.message); process.exit(1); });
