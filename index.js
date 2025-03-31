require('dotenv').config();
const express = require('express');
const sql = require('mssql');
const cors = require('cors');
const app = express();
const port = process.env.PORT || 3000;
const bcrypt = require('bcrypt');
const axios = require('axios');

const config = {
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    server: process.env.DB_SERVER,
    database: process.env.DB_DATABASE,
    options: {
        encrypt: true,
        connectTimeout: 30000,
    },
};

const allowedOrigins = [
    //'https://farmacia-app-two.vercel.app',  // <-- Sin la barra final
    /^http:\/\/localhost:\d+$/
];

app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.some(o => typeof o === 'string' ? o === origin : o.test(origin))) {
            callback(null, true);
        } else {
            callback(new Error('Origen no permitido por CORS'));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
}));

app.use(express.json());

app.post('/api/v1/ingresar', async (req, res) => {
    const { email, password } = req.body;

    try {
        const pool = await sql.connect(config);
        const request = pool.request();
        const result = await request
            .input('correo', sql.VarChar, email)
            .execute('sp_AutenticarTrabajador');

        if (result.recordset.length > 0) {
            const user = result.recordset[0];

            if (user.estado !== 'activo') {
                return res.status(403).send('Acceso denegado: el usuario está inactivo.');
            }

            const match = await bcrypt.compare(password, user.contraseña);

            if (match) {
                res.status(200).json({
                    message: 'Login successful',
                    user: {
                        id: user.id,
                        nombre: user.nombre,
                        correo: user.correo,
                        rol: user.rol,
                    },
                });
            } else {
                res.status(401).send('Invalid email or password');
            }
        } else {
            res.status(401).send('Invalid email or password');
        }
    } catch (err) {
        console.error('Error al iniciar sesión:', err.message);
        res.status(500).send('Server error');
    }
});

const authorizeRole = (roles) => {
    return (req, res, next) => {
        const userRole = req.user.rol;

        if (roles.includes(userRole)) {
            return next();
        } else {
            return res.status(403).send('No tienes permisos para acceder a esta ruta.');
        }
    };
};

app.get('/api/v1/admin', authorizeRole(['admin']), (req, res) => {
    res.status(200).send('Acceso a administrador concedido.');
});

app.post('/api/v1/registrar', async (req, res) => {
    const { nombre, correo, password, rol } = req.body;

    if (!nombre || !correo || !password || !rol) {
        return res.status(400).send('Todos los campos son obligatorios.');
    }

    try {
        const pool = await sql.connect(config);

        const hashedPassword = await bcrypt.hash(password, 10);

        await pool.request()
            .input('nombre', sql.VarChar, nombre)
            .input('correo', sql.VarChar, correo)
            .input('contraseña', sql.VarChar, hashedPassword)
            .input('rol', sql.VarChar, rol)
            .input('fecha_creacion', sql.DateTime, new Date())
            .input('estado', sql.VarChar, 'activo')
            .execute('sp_RegistrarTrabajadorTransaccional');

        res.status(201).send('Usuario registrado correctamente.');
    } catch (err) {
        if (err.message.includes('El correo ya está registrado')) {
            res.status(400).send('El correo ya está registrado.');
        } else {
            console.error('Error al registrar usuario:', err.message);
            res.status(500).send('Error al registrar usuario.');
        }
    }
});

app.get('/api/v1/trabajadores', async (req, res) => {
    try {
        const pool = await sql.connect(config);
        const result = await pool.request()
            .query('SELECT id, nombre, correo, rol, fecha_creacion, estado FROM Trabajadores');

        res.status(200).json(result.recordset);
    } catch (err) {
        console.error('Error al obtener trabajadores:', err);
        res.status(500).send('Error del servidor al obtener trabajadores');
    }
});

app.delete('/api/v1/trabajadores/:id/eliminar', async (req, res) => {
    const { id } = req.params;

    try {
        const pool = await sql.connect(config);
        const result = await pool.request()
            .input('id', sql.Int, id)
            .query('DELETE FROM Trabajadores WHERE id = @id');

        if (result.rowsAffected[0] > 0) {
            res.status(200).send('Trabajador eliminado exitosamente.');
        } else {
            res.status(404).send('Trabajador no encontrado.');
        }
    } catch (err) {
        console.error('Error al eliminar trabajador:', err);
        res.status(500).send('Error del servidor al eliminar trabajador.');
    }
});

app.delete('/api/v1/trabajadores/:id', async (req, res) => {
    try {
        const pool = await sql.connect(config);
        await pool.request()
            .input('id', sql.Int, req.params.id)
            .query('UPDATE Trabajadores SET estado = \'inactivo\' WHERE id = @id');

        res.status(200).send('Trabajador desactivado exitosamente');
    } catch (err) {
        console.error('Error al desactivar trabajador:', err);
        res.status(500).send('Error del servidor al desactivar trabajador');
    }
});

app.patch('/api/v1/trabajadores/:id/estado', async (req, res) => {
    const { id } = req.params;
    const { estado } = req.body;

    if (!estado || !['activo', 'inactivo'].includes(estado.toLowerCase())) {
        return res.status(400).send("Estado inválido. Debe ser 'activo' o 'inactivo'.");
    }

    try {
        const pool = await sql.connect(config);
        const result = await pool.request()
            .input('id', sql.Int, id)
            .input('estado', sql.VarChar, estado.toLowerCase())
            .execute('sp_ActualizarEstadoTrabajador');

        res.status(200).json({ message: `Estado del trabajador actualizado a '${estado}'.` });
    } catch (err) {
        if (err.message.includes('Trabajador no encontrado')) {
            res.status(404).send('Trabajador no encontrado.');
        } else {
            console.error('Error al actualizar estado del trabajador:', err);
            res.status(500).send('Error del servidor al actualizar estado del trabajador.');
        }
    }
});

app.get('/api/v1/keepalive', (req, res) => {
    res.status(200).send('Server is alive!');
});

app.get('/api/v1/inventarioBodega', async (req, res) => {
    try {
        const pool = await sql.connect(config);
        const result = await pool.request()
            .query(`
                SELECT
                    M.ID,
                    M.NombreGenerico,
                    M.NombreMedico,
                    M.Fabricante,
                    M.Contenido,
                    M.FormaFarmaceutica,
                    FORMAT(M.FechaFabricacion, 'yyyy-MM-dd') AS FechaFabricacion,
                    M.Presentacion,
                    FORMAT(M.FechaCaducidad, 'yyyy-MM-dd') AS FechaCaducidad,
                    M.UnidadesPorCaja,
                    M.Stock,
                    M.Precio
                FROM medicamentosBodega M;
            `);

        res.status(200).json(result.recordset);
    } catch (err) {
        console.error('Error al obtener medicamentos:', err);
        res.status(500).send('Error del servidor al obtener medicamentos');
    }
});







app.listen(port, () => {
    console.log(`Servidor en ejecución en el puerto ${port}`);
});



module.exports = app;