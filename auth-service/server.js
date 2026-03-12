'use strict';
require('dotenv').config();

const express  = require('express');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const { Pool } = require('pg');

const app  = express();
const PORT = process.env.AUTH_PORT || 3001;

app.use(express.json());

// Conexión a la base de datos
const pool = new Pool({
    host:     process.env.DB_HOST     || 'postgres',
    port:     parseInt(process.env.DB_PORT) || 5432,
    database: process.env.POSTGRES_DB || 'securepay_db',
    user:     process.env.POSTGRES_USER,
    password: process.env.POSTGRES_PASSWORD
});

// ── POST /auth/register ──────────────────────
app.post('/auth/register', async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ error: 'username, email y password son requeridos.' });
    }

    try {
        // Verificar si ya existe (consulta parametrizada - Anti-SQLi)
        const exists = await pool.query(
            'SELECT id FROM users WHERE email = $1 OR username = $2',
            [email, username]
        );
        if (exists.rows.length > 0) {
            return res.status(409).json({ error: 'El email o username ya está en uso.' });
        }

        // Hash de contraseña
        const passwordHash = await bcrypt.hash(password, 10);

        // Insertar usuario
        const result = await pool.query(
            `INSERT INTO users (username, email, password_hash)
             VALUES ($1, $2, $3)
             RETURNING id, username, email, role`,
            [username, email, passwordHash]
        );
        const user = result.rows[0];

        // Crear cuenta bancaria
        const accountNumber = `ACC-${Date.now()}`;
        await pool.query(
            'INSERT INTO accounts (user_id, account_number, balance) VALUES ($1, $2, 1000.00)',
            [user.id, accountNumber]
        );

        const token = jwt.sign(
            { userId: user.id, email: user.email, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.status(201).json({ message: 'Usuario registrado.', user, token });

    } catch (err) {
        console.error('[AUTH] Error registro:', err.message);
        res.status(500).json({ error: 'Error interno.' });
    }
});

// ── POST /auth/login ─────────────────────────
app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'email y password son requeridos.' });
    }

    try {
        // Consulta parametrizada (Anti-SQLi)
        const result = await pool.query(
            'SELECT id, username, email, password_hash, role, is_active FROM users WHERE email = $1',
            [email]
        );

        const user = result.rows[0];

        // Mensaje genérico para no revelar si el usuario existe
        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(401).json({ error: 'Credenciales incorrectas.' });
        }

        if (!user.is_active) {
            return res.status(403).json({ error: 'Cuenta desactivada.' });
        }

        const token = jwt.sign(
            { userId: user.id, email: user.email, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.json({
            message: 'Login exitoso.',
            user: { id: user.id, username: user.username, email: user.email, role: user.role },
            token
        });

    } catch (err) {
        console.error('[AUTH] Error login:', err.message);
        res.status(500).json({ error: 'Error interno.' });
    }
});

app.listen(PORT, () => console.log(`[AUTH-SERVICE] Puerto ${PORT}`));
