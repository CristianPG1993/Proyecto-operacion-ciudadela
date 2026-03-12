'use strict';

const express = require('express');
const helmet  = require('helmet'); // Hardening de cabeceras HTTP
const { body, validationResult } = require('express-validator'); // Sanitización
const db = require('./database'); // Simulación de DB con Prepared Statements

const app = express();
app.use(express.json());
app.use(helmet()); // 🛡️ Defensa en Profundidad: Protege contra ataques web comunes

// Endpoint de Transferencia con VALIDACIÓN DE ENTRADA (Anti-XSS/SQLi)
app.post('/transfer', [
    body('target_iban').isIBAN().withMessage('IBAN inválido'),
    body('amount').isFloat({ gt: 0 }).withMessage('El monto debe ser positivo'),
    body('concept').trim().escape() // 🛡️ Mitigación XSS: Escapa caracteres peligrosos
], async (req, res) => {

    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { target_iban, amount, concept } = req.body;

    try {
        // 🛡️ Mitigación SQLi: Uso de consultas parametrizadas ($1, $2...)
        const query = 'INSERT INTO transfers (target, amount, concept) VALUES ($1, $2, $3)';
        await db.query(query, [target_iban, amount, concept]);

        res.status(201).json({ message: "Transferencia procesada íntegramente." });
    } catch (err) {
        res.status(500).json({ error: "Fallo en Integridad de datos" });
    }
});

module.exports = app;
