'use strict';
require('dotenv').config();

const express    = require('express');
const helmet     = require('helmet');
const cors       = require('cors');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const { Pool }   = require('pg');
const { body, validationResult } = require('express-validator');

const app  = express();
const PORT = process.env.AUTH_SERVICE_PORT || 3001;

// =============================================
// SEGURIDAD: Cabeceras y parseo
// =============================================
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '5kb' }));

// =============================================
// CONEXIÓN A BASE DE DATOS (Mínimo Privilegio)
// Usa usuario auth_svc con permisos restringidos
// =============================================
const pool = new Pool({
    host:     process.env.DB_HOST     || 'postgres',
    port:     parseInt(process.env.DB_PORT) || 5432,
    database: process.env.POSTGRES_DB || 'securepay_db',
    user:     'auth_svc',
    password: 'Auth_Svc_P@ss_2024!',
    max:      10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000
});

// Verificar conexión al inicio
pool.connect()
    .then(client => {
        console.log('[AUTH-SERVICE] Conectado a PostgreSQL');
        client.release();
    })
    .catch(err => console.error('[AUTH-SERVICE] Error DB:', err.message));

// =============================================
// HELPERS
// =============================================
function generateAccountNumber() {
    const rand = Math.floor(Math.random() * 9000000000) + 1000000000;
    return `ACC-${rand}`;
}

function generateTokens(user) {
    const payload = {
        userId: user.id,
        email:  user.email,
        role:   user.role
    };
    const accessToken = jwt.sign(payload, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN || '1h',
        issuer:    'securepay-auth',
        audience:  'securepay-api'
    });
    return { accessToken };
}

// =============================================
// VALIDACIONES con express-validator
// =============================================
const registerValidation = [
    body('username')
        .trim()
        .isLength({ min: 3, max: 50 })
        .withMessage('El username debe tener entre 3 y 50 caracteres.')
        .matches(/^[a-zA-Z0-9_]+$/)
        .withMessage('El username solo puede contener letras, números y guiones bajos.'),
    body('email')
        .trim()
        .isEmail()
        .normalizeEmail()
        .withMessage('Email inválido.'),
    body('password')
        .isLength({ min: 8 })
        .withMessage('La contraseña debe tener mínimo 8 caracteres.')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
        .withMessage('La contraseña debe contener mayúsculas, minúsculas y números.')
];

const loginValidation = [
    body('email').trim().isEmail().normalizeEmail(),
    body('password').notEmpty()
];

// Middleware para manejar errores de validación
function handleValidation(req, res, next) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    next();
}

// =============================================
// RUTAS
// =============================================

// Health check
app.get('/auth/health', (req, res) => {
    res.json({ service: 'auth-service', status: 'ok', timestamp: new Date().toISOString() });
});

// ── POST /auth/register ──────────────────────
app.post('/auth/register', registerValidation, handleValidation, async (req, res) => {
    const { username, email, password } = req.body;
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        // Verificar si el usuario ya existe (consulta parametrizada - Anti-SQLi)
        const existsResult = await client.query(
            'SELECT id FROM users WHERE email = $1 OR username = $2',
            [email, username]
        );
        if (existsResult.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(409).json({ error: 'El email o username ya está en uso.' });
        }

        // Hash de contraseña con bcrypt (factor de costo 12)
        const passwordHash = await bcrypt.hash(password, 12);

        // Insertar usuario (consulta parametrizada)
        const userResult = await client.query(
            `INSERT INTO users (username, email, password_hash, role)
             VALUES ($1, $2, $3, 'user')
             RETURNING id, username, email, role, created_at`,
            [username, email, passwordHash]
        );
        const newUser = userResult.rows[0];

        // Crear cuenta bancaria automáticamente
        const accountNumber = generateAccountNumber();
        await client.query(
            `INSERT INTO accounts (user_id, account_number, balance, currency)
             VALUES ($1, $2, 1000.00, 'EUR')`,
            [newUser.id, accountNumber]
        );

        await client.query('COMMIT');

        const { accessToken } = generateTokens(newUser);

        res.status(201).json({
            message: 'Usuario registrado correctamente.',
            user:    { id: newUser.id, username: newUser.username, email: newUser.email, role: newUser.role },
            account: { accountNumber, balance: 1000.00, currency: 'EUR' },
            accessToken
        });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error('[AUTH] Error en registro:', err.message);
        res.status(500).json({ error: 'Error interno al registrar el usuario.' });
    } finally {
        client.release();
    }
});

// ── POST /auth/login ─────────────────────────
app.post('/auth/login', loginValidation, handleValidation, async (req, res) => {
    const { email, password } = req.body;

    try {
        // Consulta parametrizada (Anti-SQLi)
        const result = await pool.query(
            `SELECT id, username, email, password_hash, role, is_active, failed_attempts, locked_until
             FROM users WHERE email = $1`,
            [email]
        );

        const user = result.rows[0];

        // Mensaje genérico para evitar enumeración de usuarios
        if (!user) {
            return res.status(401).json({ error: 'Credenciales incorrectas.' });
        }

        // Verificar si la cuenta está bloqueada
        if (user.locked_until && new Date() < new Date(user.locked_until)) {
            return res.status(423).json({
                error: 'Cuenta bloqueada temporalmente por múltiples intentos fallidos.',
                lockedUntil: user.locked_until
            });
        }

        // Verificar si la cuenta está activa
        if (!user.is_active) {
            return res.status(403).json({ error: 'Cuenta desactivada. Contacta al administrador.' });
        }

        // Verificar contraseña con bcrypt (comparación en tiempo constante)
        const passwordValid = await bcrypt.compare(password, user.password_hash);

        if (!passwordValid) {
            // Incrementar intentos fallidos (máx. 5 -> bloqueo 15 min)
            const newAttempts = user.failed_attempts + 1;
            const lockQuery = newAttempts >= 5
                ? `UPDATE users SET failed_attempts = $1, locked_until = NOW() + INTERVAL '15 minutes' WHERE id = $2`
                : `UPDATE users SET failed_attempts = $1 WHERE id = $2`;
            await pool.query(lockQuery, [newAttempts, user.id]);
            return res.status(401).json({ error: 'Credenciales incorrectas.' });
        }

        // Restablecer intentos fallidos tras login exitoso
        await pool.query(
            'UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = $1',
            [user.id]
        );

        const { accessToken } = generateTokens(user);

        res.json({
            message: 'Login exitoso.',
            user:    { id: user.id, username: user.username, email: user.email, role: user.role },
            accessToken
        });

    } catch (err) {
        console.error('[AUTH] Error en login:', err.message);
        res.status(500).json({ error: 'Error interno al iniciar sesión.' });
    }
});

// ── GET /auth/verify ─────────────────────────
// Endpoint interno para que el gateway verifique tokens
app.get('/auth/verify', (req, res) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ valid: false, error: 'Token requerido.' });
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET, {
            issuer:   'securepay-auth',
            audience: 'securepay-api'
        });
        res.json({ valid: true, user: { userId: decoded.userId, email: decoded.email, role: decoded.role } });
    } catch (err) {
        res.status(401).json({ valid: false, error: err.message });
    }
});

// ── GET /auth/profile ────────────────────────
app.get('/auth/profile', async (req, res) => {
    const userId = req.headers['x-user-id'];
    if (!userId) {
        return res.status(401).json({ error: 'No autenticado.' });
    }

    try {
        const result = await pool.query(
            `SELECT u.id, u.username, u.email, u.role, u.created_at,
                    a.account_number, a.balance, a.currency
             FROM users u
             LEFT JOIN accounts a ON a.user_id = u.id
             WHERE u.id = $1 AND u.is_active = TRUE`,
            [parseInt(userId)]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado.' });
        }

        const row = result.rows[0];
        res.json({
            user: {
                id: row.id, username: row.username,
                email: row.email, role: row.role, createdAt: row.created_at
            },
            account: {
                accountNumber: row.account_number,
                balance: row.balance,
                currency: row.currency
            }
        });
    } catch (err) {
        console.error('[AUTH] Error en profile:', err.message);
        res.status(500).json({ error: 'Error interno.' });
    }
});

// =============================================
// INICIO DEL SERVIDOR
// =============================================
app.listen(PORT, () => {
    console.log(`[AUTH-SERVICE] Escuchando en puerto ${PORT}`);
});
