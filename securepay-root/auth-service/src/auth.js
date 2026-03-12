'use strict';

const jwt    = require('jsonwebtoken');
const bcrypt = require('bcrypt');

// Generar Token con Rol Limitado (Blast Radius Reduction)
const generateToken = (user) => {
    return jwt.sign(
        { id: user.id, role: 'TRANSFER_USER' }, // Solo permiso para transferir, no admin
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
    );
};

module.exports = { generateToken, bcrypt };
