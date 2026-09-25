// Cargar variables de entorno
require('dotenv').config();

// Importar librerías
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const authenticateToken = require('./middleware/autenticacion_middleware');

// Configuración del servidor y de la base de datos
const app = express();
app.use(express.json()); // Permite al servidor leer datos JSON
app.use(cors()); // Permite solicitudes desde el frontend

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;
const supabase = createClient(supabaseUrl, supabaseAnonKey);

const port = 3000;
app.listen(port, () => {
    console.log(`Servidor escuchando en http://localhost:${port}`);
});

// Endpoint para el registro de usuarios
app.post('/registrar', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Validar que no falten datos
        if (!username || !password) {
            return res.status(400).json({ error: 'El nombre de usuario y contraseña son requeridos' });
        }

        // Hashear la contraseña
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Insertar el nuevo usuario en Supabase
        const { data, error } = await supabase
            .from('usuarios')
            .insert([{ username, password: hashedPassword }]);

        if (error) {
            console.error('Error durante el registro:', error);
            return res.status(500).json({ error: 'El registro de usuario flló' });
        }

        res.status(201).json({ message: 'Usuario registrado correctamente' });
    } catch (error) {
        console.error('Server error:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Endpoint para el login de usuarios
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // 1. Buscar el usuario en la base de datos
        const { data: users, error } = await supabase
            .from('usuarios')
            .select('password')
            .eq('username', username)
            .single();

        if (error || !users) {
            return res.status(401).json({ error: 'Credenciales inválidas.' });
        }

        // 2. Comparar la contraseña ingresada con la hasheada
        const isMatch = await bcrypt.compare(password, users.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Credenciales inválidas.' });
        }

        // 3. Generar un token de autenticación (JWT)
        const token = jwt.sign({ username: username }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.status(200).json({ message: 'Inicio de sesión exitoso!', token });
    } catch (error) {
        console.error('Server error:', error);
        res.status(500).json({ error: 'Eror interno del servidor.' });
    }
});

const path = require('path');
app.use(express.static(path.join(__dirname, 'public')));

// Endpoint o Ruta de ejemplo para un recurso protegido
// Esta ruta solo será accesible si se proporciona un JWT válido.
app.get('/recurso-protegido', authenticateToken, (req, res) => {
    // Si se llega a esta función, quiere decir que el middleware 'authenticateToken'
    // ya verificó el JWT y lo encontró válido.
    // La información del usuario está disponible en `req.user`.
    res.status(200).json({
        message: `Bienvenido al recurso protegido, ${req.user.username}!`,
        data: 'Esta información es sólo para usuarios autenticados'
    });
});