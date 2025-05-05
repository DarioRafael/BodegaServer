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
    'https://farmacia-app-two.vercel.app',  // <-- Sin la barra final
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
            .input('ID', sql.Int, id) // Asegúrate de que 'ID' es el nombre correcto de la columna
            .input('Stock', sql.Int, cantidad)
            .query(`
                UPDATE medicamentosBodega
                SET Stock = Stock + @Stock
                WHERE ID = @ID
            `);

        res.status(200).json({ mensaje: 'Medicamento reabastecido correctamente' });
    } catch (err) {
        console.error('Error al reabastecer el medicamento:', err);
        res.status(500).json({ mensaje: 'Error del servidor al reabastecer el medicamento' });
    }
});

app.put('/api/v1/medicamentos-bodega/reabastecer-multiple', async (req, res) => {
    const productos = req.body; // Se espera un array de objetos { id, cantidad }

    if (!Array.isArray(productos) || productos.length === 0) {
        return res.status(400).json({ mensaje: 'Debe proporcionar una lista válida de productos para reabastecer' });
    }

    try {
        const pool = await sql.connect(config);

        for (const producto of productos) {
            const { id, cantidad } = producto;

            if (!id || cantidad <= 0) {
                console.warn(`ID inválido o cantidad incorrecta para el producto:`, producto);
                continue; // Saltar este producto y seguir con el siguiente
            }

            await pool.request()
                .input('ID', sql.Int, id)
                .input('Stock', sql.Int, cantidad)
                .query(`
                    UPDATE medicamentosBodega
                    SET Stock = Stock + @Stock
                    WHERE ID = @ID
                `);
        }

        res.status(200).json({ mensaje: 'Medicamentos reabastecidos correctamente' });
    } catch (err) {
        console.error('Error al reabastecer los medicamentos:', err);
        res.status(500).json({ mensaje: 'Error del servidor al reabastecer los medicamentos' });
    }
});


app.get('/api/v1/medicamentos-bodega', async (req, res) => {
    try {
        const pool = await sql.connect(config);
        const result = await pool.request().query(`
            SELECT ID, NombreGenerico, Stock, FORMAT(FechaFabricacion, 'yyyy-MM-dd') AS FechaFabricacion
            FROM medicamentosBodega
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

    // Validación de los datos de entrada
    if (!descripcion || !monto || !tipo || (tipo.toLowerCase() !== 'ingreso' && tipo.toLowerCase() !== 'egreso')) {
        return res.status(400).json({ mensaje: 'Debe proporcionar una descripción, monto y tipo válido ("ingreso" o "egreso")' });
    }

    try {
        const pool = await sql.connect(config);

        // Insertar la transacción (sin especificar el ID, ya que debería ser autogenerado)
        await pool.request()
            .input('descripcion', sql.VarChar(255), descripcion)
            .input('monto', sql.Decimal(10, 2), monto)
            .input('tipo', sql.VarChar(50), tipo)
            .query(
                `INSERT INTO MovimientosBodega (descripcion, monto, tipo, fecha)
                 VALUES (@descripcion, @monto, @tipo, GETDATE())`
            );

        // Actualizar saldo (ingresos o egresos)
        if (tipo.toLowerCase() === 'ingreso') {
            await pool.request()
                .input('Monto', sql.Decimal(10, 2), monto)
                .query(
                    `UPDATE SaldoBodega
                     SET saldo = saldo + @Monto, ingresos = ingresos + @Monto
                     WHERE id = 1`
                );
        } else {
            await pool.request()
                .input('Monto', sql.Decimal(10, 2), monto)
                .query(
                    `UPDATE SaldoBodega
                     SET saldo = saldo - @Monto, egresos = egresos + @Monto
                     WHERE id = 1`
                );
        }

        res.status(201).json({ mensaje: 'Transacción registrada correctamente' });
    } catch (err) {
        console.error('Error al registrar transacción:', err);
        res.status(500).json({ mensaje: 'Error del servidor al registrar transacción' });
    }
});


app.get('/api/v1/movimientosGet', async (req, res) => {
    try {
        const pool = await sql.connect(config);

        // Query to get all movements from MovimientosBodega
        const result = await pool.request()
            .query('SELECT id, descripcion, monto, tipo, fecha FROM MovimientosBodega ORDER BY fecha DESC');

        res.status(200).json({
            movimientos: result.recordset
        });
    } catch (err) {
        console.error('Error al obtener movimientos:', err);
        res.status(500).json({ mensaje: 'Error del servidor al obtener los movimientos' });
    }
});






// Pedidos

// Endpoint POST específico para cancelar pedidos desde la bodega
app.post('/api/v1/bodega/cancelar-pedido', async (req, res) => {
    const {
        pedido_id,
        motivo
    } = req.body;

    // Validación de campos obligatorios
    if (!pedido_id) {
        return res.status(400).json({
            message: 'Se requiere el ID del pedido'
        });
    }

    // Validar que tenga motivo
    if (!motivo) {
        return res.status(400).json({
            message: 'Se requiere especificar un motivo para cancelar el pedido'
        });
    }

    try {
        const pool = await sql.connect(config);

        // Verificar si el pedido existe
        const pedidoResult = await pool.request()
            .input('id', sql.Int, pedido_id)
            .query('SELECT * FROM pedidos WHERE id = @id');

        if (pedidoResult.recordset.length === 0) {
            return res.status(404).json({ message: 'Pedido no encontrado' });
        }

        const pedido = pedidoResult.recordset[0];

        // Verificar que el pedido esté en un estado que permita la cancelación
        if (pedido.estado === 'cancelado') {
            return res.status(400).json({ message: 'Este pedido ya fue cancelado anteriormente' });
        }

        if (pedido.estado === 'completado') {
            return res.status(400).json({ message: 'No se puede cancelar un pedido que ya fue completado' });
        }

        // Iniciar transacción
        const transaction = new sql.Transaction(pool);
        await transaction.begin();

        try {
            const request = new sql.Request(transaction);

            // Actualizar el pedido a estado cancelado
            await request
                .input('id', sql.Int, pedido_id)
                .input('estado', sql.NVarChar(20), 'cancelado')
                .input('motivo', sql.NVarChar(sql.MAX), `Cancelado por bodega: ${motivo}`)
                .query(`
                    UPDATE pedidos 
                    SET estado = @estado, 
                        fecha_actualizacion = GETDATE(),
                        notas = CASE 
                                  WHEN notas IS NULL OR notas = '' THEN @motivo
                                  ELSE notas + '; ' + @motivo
                                END
                    WHERE id = @id
                `);

            await transaction.commit();

            res.status(200).json({
                message: 'Pedido cancelado exitosamente',
                pedido_id,
                estado: 'cancelado',
                motivo
            });
        } catch (err) {
            await transaction.rollback();
            console.error('Error al cancelar el pedido:', err);
            res.status(500).json({
                message: 'Error al cancelar el pedido',
                error: err.message
            });
        }
    } catch (err) {
        console.error('Error en la conexión:', err);
        res.status(500).json({
            message: 'Error de conexión a la base de datos',
            error: err.message
        });
    }
});

app.post('/api/v1/bodega/confirmar-pedido', async (req, res) => {
    const { pedido_id } = req.body;

    // Validación de campos obligatorios
    if (!pedido_id) {
        return res.status(400).json({
            message: 'Se requiere el ID del pedido'
        });
    }

    try {
        const pool = await sql.connect(config);

        // Verificar si el pedido existe
        const pedidoResult = await pool.request()
            .input('id', sql.Int, pedido_id)
            .query('SELECT * FROM pedidos WHERE id = @id');

        if (pedidoResult.recordset.length === 0) {
            return res.status(404).json({ message: 'Pedido no encontrado' });
        }

        const pedido = pedidoResult.recordset[0];

        // Verificar que el pedido no esté cancelado o completado
        if (pedido.estado === 'cancelado') {
            return res.status(400).json({ message: 'No se puede confirmar un pedido que ha sido cancelado' });
        }

        if (pedido.estado === 'completado') {
            return res.status(400).json({ message: 'No se puede confirmar un pedido que ya fue completado' });
        }

        if (pedido.estado === 'confirmado') {
            return res.status(400).json({ message: 'Este pedido ya está confirmado' });
        }

        // Iniciar transacción
        const transaction = new sql.Transaction(pool);
        await transaction.begin();

        try {
            const request = new sql.Request(transaction);

            // Actualizar el pedido a estado confirmado
            await request
                .input('id', sql.Int, pedido_id)
                .input('estado', sql.NVarChar(20), 'confirmado')
                .input('nota', sql.NVarChar(sql.MAX), 'Pedido confirmado por bodega')
                .query(`
                    UPDATE pedidos 
                    SET estado = @estado, 
                        fecha_actualizacion = GETDATE(),
                        notas = CASE 
                                  WHEN notas IS NULL OR notas = '' THEN @nota
                                  ELSE notas + '; ' + @nota
                                END
                    WHERE id = @id
                `);

            await transaction.commit();

            res.status(200).json({
                message: 'Pedido confirmado exitosamente',
                pedido_id,
                estado: 'confirmado'
            });
        } catch (err) {
            await transaction.rollback();
            console.error('Error al confirmar el pedido:', err);
            res.status(500).json({
                message: 'Error al confirmar el pedido',
                error: err.message
            });
        }
    } catch (err) {
        console.error('Error en la conexión:', err);
        res.status(500).json({
            message: 'Error de conexión a la base de datos',
            error: err.message
        });
    }
});

// Endpoint para marcar un pedido como completado
app.post('/api/v1/bodega/marcar-pedido-completado', async (req, res) => {
    const { pedido_id } = req.body;

    if (!pedido_id) {
        return res.status(400).json({
            message: 'Se requiere el ID del pedido'
        });
    }

    try {
        const pool = await sql.connect(config);

        // Verificar si el pedido existe
        const pedidoResult = await pool.request()
            .input('id', sql.Int, pedido_id)
            .query('SELECT * FROM pedidos WHERE id = @id');

        if (pedidoResult.recordset.length === 0) {
            return res.status(404).json({ message: 'Pedido no encontrado' });
        }

        const pedido = pedidoResult.recordset[0];

        // Verificar si el pedido está cancelado o ya completado
        if (pedido.estado === 'cancelado') {
            return res.status(400).json({ message: 'No se puede completar un pedido cancelado' });
        }

        if (pedido.estado === 'completado') {
            return res.status(400).json({ message: 'Este pedido ya está completado' });
        }

        // Iniciar la transacción
        const transaction = new sql.Transaction(pool);
        await transaction.begin();

        try {
            const request = new sql.Request(transaction);

            // Marcar el pedido como completado
            await request
                .input('id', sql.Int, pedido_id)
                .input('estado', sql.NVarChar(20), 'completado')
                .query(`
                    UPDATE pedidos
                    SET estado = @estado,
                        fecha_actualizacion = GETDATE()
                    WHERE id = @id
                `);

            await transaction.commit();

            res.status(200).json({
                message: 'Pedido marcado como completado exitosamente',
                pedido_id,
                estado: 'completado'
            });

        } catch (err) {
            await transaction.rollback();
            console.error('Error al marcar pedido como completado:', err);
            res.status(500).json({
                message: 'Error al marcar pedido como completado',
                error: err.message
            });
        }
    } catch (err) {
        console.error('Error en la conexión:', err);
        res.status(500).json({
            message: 'Error de conexión a la base de datos',
            error: err.message
        });
    }
});

app.post('/api/v1/bodega/actualizar-stock', async (req, res) => {
    const { tablaFarmacia, productos } = req.body;

    // Validaciones iniciales
    if (!tablaFarmacia || !productos || !Array.isArray(productos)) {
        return res.status(400).json({
            message: 'Se requiere el nombre de la tabla de farmacia y una lista de productos'
        });
    }

    // Validar que la tablaFarmacia sea segura
    const tablaSegura = /^[a-zA-Z0-9_]+$/.test(tablaFarmacia);
    if (!tablaSegura) {
        return res.status(400).json({ message: 'Nombre de tabla inválido' });
    }

    try {
        const pool = await sql.connect(config);
        const transaction = new sql.Transaction(pool);
        await transaction.begin();

        try {
            const request = new sql.Request(transaction);
            const resultadosActualizacion = [];

            for (const producto of productos) {
                const { nombreProducto, cantidadProducto } = producto;

                // Validar que el nombre del producto no esté duplicado
                if (productos.findIndex(p => p.nombreProducto === nombreProducto) !== productos.indexOf(producto)) {
                    resultadosActualizacion.push({
                        nombre: nombreProducto,
                        status: 'error',
                        mensaje: 'Producto duplicado en la solicitud'
                    });
                    continue;
                }

                // Buscar el producto con una búsqueda más flexible
                const busquedaProducto = await request
                    .input('nombreProducto', sql.NVarChar(255), nombreProducto)
                    .query(`
                        SELECT NombreGenerico, Stock 
                        FROM ${tablaFarmacia} 
                        WHERE NombreGenerico LIKE @nombreProducto
                        OR REPLACE(LOWER(NombreGenerico), ' ', '') LIKE REPLACE(LOWER(@nombreProducto), ' ', '')
                    `);

                if (busquedaProducto.recordset.length === 0) {
                    resultadosActualizacion.push({
                        nombre: nombreProducto,
                        status: 'error',
                        mensaje: 'Producto no encontrado en el inventario'
                    });
                    continue;
                }

                const productoEncontrado = busquedaProducto.recordset[0];

                try {
                    await request
                        .input('nombreGenerico', sql.NVarChar(255), productoEncontrado.NombreGenerico)
                        .input('cantidadProducto', sql.Int, cantidadProducto)
                        .query(`
                            UPDATE ${tablaFarmacia}
                            SET Stock = Stock + @cantidadProducto
                            WHERE NombreGenerico = @nombreGenerico
                        `);

                    resultadosActualizacion.push({
                        nombre: nombreProducto,
                        status: 'success',
                        stockAnterior: productoEncontrado.Stock,
                        stockActualizado: productoEncontrado.Stock - cantidadProducto
                    });
                } catch (errorActualizacion) {
                    resultadosActualizacion.push({
                        nombre: nombreProducto,
                        status: 'error',
                        mensaje: 'Error al actualizar el stock',
                        detalleError: errorActualizacion.message
                    });
                }
            }

            await transaction.commit();

            res.status(200).json({
                message: 'Proceso de actualización de stock completado',
                tabla_farmacia: tablaFarmacia,
                resultados: resultadosActualizacion,
                resumen: {
                    total: resultadosActualizacion.length,
                    exitosos: resultadosActualizacion.filter(r => r.status === 'success').length,
                    errores: resultadosActualizacion.filter(r => r.status === 'error').length
                }
            });

        } catch (errorTransaccion) {
            await transaction.rollback();
            console.error('Error en la transacción:', errorTransaccion);
            res.status(500).json({
                message: 'Error al procesar la actualización de stock',
                error: errorTransaccion.message
            });
        }
    } catch (errorConexion) {
        console.error('Error de conexión a la base de datos:', errorConexion);
        res.status(500).json({
            message: 'Error de conexión a la base de datos',
            error: errorConexion.message
        });
    }
});





app.post('/api/v1/farmacias/cancelar-pedido', async (req, res) => {
    const {
        pedido_id,
        motivo
    } = req.body;

    // Validación de campos obligatorios
    if (!pedido_id) {
        return res.status(400).json({
            message: 'Se requiere el ID del pedido'
        });
    }

    // Validar que tenga motivo
    if (!motivo) {
        return res.status(400).json({
            message: 'Se requiere especificar un motivo para cancelar el pedido'
        });
    }

    try {
        const pool = await sql.connect(config);

        // Verificar si el pedido existe
        const pedidoResult = await pool.request()
            .input('id', sql.Int, pedido_id)
            .query('SELECT * FROM pedidos WHERE id = @id');

        if (pedidoResult.recordset.length === 0) {
            return res.status(404).json({ message: 'Pedido no encontrado' });
        }

        const pedido = pedidoResult.recordset[0];

        // Verificar que el pedido esté en un estado que permita la cancelación
        if (pedido.estado === 'cancelado') {
            return res.status(400).json({ message: 'Este pedido ya fue cancelado anteriormente' });
        }

        if (pedido.estado === 'completado') {
            return res.status(400).json({ message: 'No se puede cancelar un pedido que ya fue completado' });
        }

        // Iniciar transacción
        const transaction = new sql.Transaction(pool);
        await transaction.begin();

        try {
            const request = new sql.Request(transaction);

            // Actualizar el pedido a estado cancelado con sintaxis MySQL
            await request
                .input('id', sql.Int, pedido_id)
                .input('estado', sql.NVarChar(20), 'cancelado')
                .input('motivo', sql.NVarChar(sql.MAX), `Cancelado por farmacia: ${motivo}`)
                .query(`
                    UPDATE pedidos
                    SET estado = @estado,
                        fecha_actualizacion = NOW(),
                        notas = CASE
                                    WHEN notas IS NULL OR notas = '' THEN @motivo
                                    ELSE CONCAT(notas, '; ', @motivo)
                            END
                    WHERE id = @id;
                `);

            await transaction.commit();

            res.status(200).json({
                message: 'Pedido cancelado exitosamente',
                pedido_id,
                estado: 'cancelado',
                motivo
            });
        } catch (err) {
            await transaction.rollback();
            console.error('Error al cancelar el pedido:', err);
            res.status(500).json({
                message: 'Error al cancelar el pedido',
                error: err.message
            });
        }
    } catch (err) {
        console.error('Error en la conexión:', err);
        res.status(500).json({
            message: 'Error de conexión a la base de datos',
            error: err.message
        });
    }
});




app.get('/api/v1/farmacia-cesar/pedidos', async (req, res) => {
    try {
        // Obtener datos de la API original
        const response = await axios.get('https://farmacia-api.loca.lt/api/pedidos', {
            // Aquí puedes añadir headers de autenticación si son necesarios
            headers: {
                // 'Authorization': `Bearer ${process.env.FARMACIA_CESAR_TOKEN}`
            }
        });

        // Si la respuesta es exitosa, transformar los datos al formato esperado
        if (response.status === 200) {
            // Transformar el array en un objeto con propiedad 'pedidos'
            const transformedData = {
                pedidos: response.data
            };

            res.status(200).json(transformedData);
        } else {
            // Si hay algún error, devolverlo
            res.status(response.status).json({
                error: 'Error al obtener datos de Farmacia Cesar',
                details: response.statusText
            });
        }
    } catch (error) {
        console.error('Error al procesar la solicitud:', error);

        // Devolver un error detallado
        res.status(500).json({
            error: 'Error interno del servidor',
            message: error.message,
            details: error.response ? error.response.data : null
        });
    }
});










app.listen(port, () => {
    console.log(`Servidor en ejecución en el puerto ${port}`);
});



module.exports = app;