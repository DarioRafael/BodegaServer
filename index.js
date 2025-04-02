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

app.get('/api/v1/inventarioBodega/bajoStock', async (req, res) => {
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
                FROM medicamentosBodega M
                WHERE M.Stock < 50
                ORDER BY M.Stock ASC;
            `);

        res.status(200).json(result.recordset);
    } catch (err) {
        console.error('Error al obtener medicamentos con stock bajo:', err);
        res.status(500).json({
            error: 'Error del servidor al obtener medicamentos con stock bajo',
            details: err.message
        });
    }
});


app.post('/api/v1/ventas-bodega', async (req, res) => {
    const { detalles } = req.body; // detalles es un array con { IDMedicamento, Stock, PrecioUnitario, PrecioSubtotal }

    if (!detalles || !Array.isArray(detalles) || detalles.length === 0) {
        return res.status(400).json({ mensaje: 'Debe incluir al menos un medicamento en la venta' });
    }

    try {
        const pool = await sql.connect(config);

        // Crear la venta y obtener el ID generado
        const ventaResult = await pool.request()
            .query('INSERT INTO VentasBodega (FechaVenta) OUTPUT INSERTED.IDVenta VALUES (GETDATE())');

        const IDVenta = ventaResult.recordset[0].IDVenta;

        for (const item of detalles) {
            await pool.request()
                .input('IDVenta', sql.Int, IDVenta)
                .input('IDMedicamento', sql.Int, item.IDMedicamento)
                .input('Stock', sql.Int, item.Stock)
                .input('PrecioUnitario', sql.Decimal(10, 2), item.PrecioUnitario)
                .input('PrecioSubtotal', sql.Decimal(10, 2), item.PrecioSubtotal)
                .query(`
                    INSERT INTO DetallesVentaBodega (IDVenta, IDMedicamento, Stock, PrecioUnitario, PrecioSubtotal)
                    VALUES (@IDVenta, @IDMedicamento, @Stock, @PrecioUnitario, @PrecioSubtotal)
                `);

            // Reducir el stock del medicamento
            await pool.request()
                .input('IDMedicamento', sql.Int, item.IDMedicamento)
                .input('Stock', sql.Int, item.Stock)
                .query(`
                    UPDATE MedicamentosBodega
                    SET Stock = Stock - @Stock
                    WHERE IDMedicamento = @IDMedicamento
                `);
        }

        res.status(201).json({ mensaje: 'Venta registrada correctamente', IDVenta });
    } catch (err) {
        console.error('Error al registrar la venta:', err);
        res.status(500).json({ mensaje: 'Error del servidor al registrar la venta' });
    }
});

app.put('/api/v1/medicamentos-bodega/:id/reabastecer', async (req, res) => {
    const { id } = req.params;
    const { cantidad } = req.body;

    if (!cantidad || cantidad <= 0) {
        return res.status(400).json({ mensaje: 'Debe proporcionar una cantidad válida para reabastecer' });
    }

    try {
        const pool = await sql.connect(config);

        await pool.request()
            .input('IDMedicamento', sql.Int, id)
            .input('Stock', sql.Int, cantidad)
            .query(`
                UPDATE MedicamentosBodega
                SET Stock = Stock + @Stock
                WHERE IDMedicamento = @IDMedicamento
            `);

        res.status(200).json({ mensaje: 'Medicamento reabastecido correctamente' });
    } catch (err) {
        console.error('Error al reabastecer el medicamento:', err);
        res.status(500).json({ mensaje: 'Error del servidor al reabastecer el medicamento' });
    }
});

app.get('/api/v1/medicamentos-bodega', async (req, res) => {
    try {
        const pool = await sql.connect(config);
        const result = await pool.request().query(`
            SELECT IDMedicamento, Nombre, Stock, FORMAT(FechaFabricacion, 'yyyy-MM-dd') AS FechaFabricacion
            FROM MedicamentosBodega
        `);

        res.status(200).json(result.recordset);
    } catch (err) {
        console.error('Error al obtener medicamentos:', err);
        res.status(500).json({ mensaje: 'Error del servidor al obtener medicamentos' });
    }
});

app.get('/api/v1/saldo-bodega', async (req, res) => {
    try {
        const pool = await sql.connect(config);
        const result = await pool.request()
            .query('SELECT saldo, ingresos, egresos FROM SaldoBodega WHERE id = 1');

        if (result.recordset.length > 0) {
            res.status(200).json(result.recordset[0]);
        } else {
            res.status(404).json({ mensaje: 'Información de saldo no encontrada' });
        }
    } catch (err) {
        console.error('Error al obtener saldo:', err);
        res.status(500).json({ mensaje: 'Error del servidor al obtener saldo' });
    }
});

app.post('/api/v1/transacciones-bodega', async (req, res) => {
    const { descripcion, monto, tipo } = req.body;

    if (!descripcion || !monto || !tipo || (tipo.toLowerCase() !== 'ingreso' && tipo.toLowerCase() !== 'egreso')) {
        return res.status(400).json({ mensaje: 'Debe proporcionar una descripción, monto y tipo válido ("ingreso" o "egreso")' });
    }

    try {
        const pool = await sql.connect(config);

        // Obtener ID para la nueva transacción
        const idResult = await pool.request()
            .query('SELECT ISNULL(MAX(ID), 0) + 1 AS nextId FROM MovimientosBodega');
        const nextId = idResult.recordset[0].nextId;

        // Insertar la transacción
        await pool.request()
            .input('ID', sql.Int, nextId)
            .input('Descripcion', sql.VarChar(255), descripcion)
            .input('Monto', sql.Decimal(10, 2), monto)
            .input('Tipo', sql.VarChar(50), tipo)
            .query(`
                INSERT INTO MovimientosBodega (ID, Descripcion, Monto, Tipo, Fecha)
                VALUES (@ID, @Descripcion, @Monto, @Tipo, GETDATE())
            `);

        // Actualizar saldo
        if (tipo.toLowerCase() === 'ingreso') {
            await pool.request()
                .input('Monto', sql.Decimal(10, 2), monto)
                .query(`
                    UPDATE SaldoBodega
                    SET Saldo = Saldo + @Monto, Ingresos = Ingresos + @Monto
                    WHERE ID = 1
                `);
        } else {
            await pool.request()
                .input('Monto', sql.Decimal(10, 2), monto)
                .query(`
                    UPDATE SaldoBodega
                    SET Saldo = Saldo - @Monto, Egresos = Egresos + @Monto
                    WHERE ID = 1
                `);
        }

        res.status(201).json({ mensaje: 'Transacción registrada correctamente', ID: nextId });
    } catch (err) {
        console.error('Error al registrar transacción:', err);
        res.status(500).json({ mensaje: 'Error del servidor al registrar transacción' });
    }
});


app.listen(port, () => {
    console.log(`Servidor en ejecución en el puerto ${port}`);
});



module.exports = app;