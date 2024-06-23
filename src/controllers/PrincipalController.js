const crypto = require('crypto');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const MemoryStream = require('memorystream');

const Utils = require('../controllers/Utils'); 
const utils = new Utils();

// Directorio donde se guardarán los archivos subidos
const uploadDir = path.join(__dirname, '../archivos');
const firmasDir = path.join(__dirname, '../firmas');

if (!fs.existsSync(uploadDir)) { //Genera carpeta de archivos si no existe
    fs.mkdirSync(uploadDir);
}

if (!fs.existsSync(firmasDir)) { //genera carpeta de firmas si no existe
    fs.mkdirSync(firmasDir);
}
 
const storage = multer.diskStorage({ //Para la subida de archivos
    destination: uploadDir,
    filename: function (req, file, cb) {
        cb(null, file.originalname);
    }
});

const upload = multer({ storage }).single('file'); //para manejar la subida de archivos

const checkFileExists = (filePath) => {                     //FUNCIÓN ASÍNCRONA QUE UTILIZA UPLOAD DE MULTER
    return fs.promises.access(filePath, fs.constants.F_OK) //comprueba si el archivo ya esta guardado
        .then(() => true)
        .catch(() => false);
};

function checkIfFileExists(filePath) { //FUNCIÓN SINCRONA
    try {
        // Verificar si el archivo existe
        fs.accessSync(filePath, fs.constants.F_OK);
        return true;
    } catch (err) {
        if (err.code === 'ENOENT') {
            return false;
        } else {
            throw err;
        }
    }
}

//Realiza la misma consulta que en principal, solo que aquí vuelve a cargarlas una vez que se sube un archivo
function actualizarNotificaciones(req, res, callback){
    req.getConnection((err, conn) => {
        if (err) {
            console.error('Error connecting to the database:', err);
            return res.status(500).send('Database connection error');
        }
        //aquí habría que hacer una de las comprobaciones de si ya firmó
        conn.query('SELECT name,envia,firmas FROM archivos WHERE recibe != ?',[req.session.matricula], (err, results) => {
            if (err) {
                console.error('Error fetching users from the database:', err);
            }
            let notifications = utils.obtenerNotificaciones(results, req.session.matricula);
            req.session.notifications = notifications;
            callback();
        });
    });
}
//cambia la base de datos cuando se firma
function actualizarBaseNotificaciones(req, res, firmas, archivo, callback){
    req.getConnection((err, conn) => {
        if (err) {
            console.error('Error connecting to the database:', err);
            return res.status(500).send('Database connection error');
        }
        //aquí habría que hacer una de las comprobaciones de si ya firmó
        conn.query('UPDATE archivos SET firmas = ? WHERE name = ?',[firmas, archivo], (err, results) => {
            if (err) {
                console.error('Error fetching users from the database:', err);
            }
            callback();
        });
    });
}

// Función para verificar el documento firmado
function verifySignedDocument(documentContent, signatureDoc, publicKey) {
    // Calcular el hash del contenido del documento
    const documentHash = utils.calculateHash(documentContent, 'base64');
    for (let signature of signatureDoc) {
        if (utils.verifySignature(documentHash, signature, publicKey)) {
            return true;  // Devuelve true y sale de la función en cuanto encuentre una coincidencia válida
        }
    }
    return false;  // Si no se encuentra ninguna coincidencia válida, devuelve false
}

//Funcion para manejar el renderizado y carga de datos de la pantalla principal
function principal(req, res){
    if(req.session.loggedin != true){
        res.redirect('/login');
    } else if (req.session.protectKey && req.session.protectKey.trim() !== ''){// protectKey no está vacío aún
        // Limpiar la sesión después de la descarga para asegurar que no se pueda descargar nuevamente
        delete req.session.protectKey;
        res.redirect('/principal');
    }else{
        req.getConnection((err, conn) => {
            if (err) {
                console.error('Error connecting to the database:', err);
                return res.status(500).send('Database connection error');
            }
            //aquí habría que hacer una de las comprobaciones de si ya firmó
            conn.query('SELECT name,envia,firmas FROM archivos WHERE recibe != ?',[req.session.matricula], (err, results) => {
                if (err) {
                    console.error('Error fetching users from the database:', err);
                }
                let notifications = utils.obtenerNotificaciones(results, req.session.matricula);
                req.session.notifications = notifications;
                res.render('principal/index', {name: req.session.name, notifications: req.session.notifications, matricula: req.session.matricula, privateKey: req.session.privateKey});
            });
        });
    } 
}

//Funcion para manejar el renderizado y carga de datos de la pantalla de descarga de clave
function alerta(req, res){
    if(req.session.loggedin != true){
        res.redirect('/login');
    } else if (req.session.protectKey && req.session.protectKey.trim() !== '') {
        // protectKey no está vacío
        res.render('principal/alerta', {
            protectKey: req.session.protectKey
        });
    } else {
        // protectKey está vacío
        res.redirect('/principal');
    }
}

//Funcion para manejar el renderizado y carga de datos de la pantalla "SIGN DOCUMENT"
function firmar(req, res){
    if(req.session.loggedin != true){
        res.redirect('/login');
    } else{
        res.render('principal/firmar', { name: req.session.name, notifications: req.session.notifications, matricula: req.session.matricula, privateKey: req.session.privateKey});
    } 
}

//Funcion para manejar el renderizado y carga de datos de la pantalla "UPLOAD CONFIDENTIAL MINUTE"
function uploadf(req, res){
    if(req.session.loggedin != true){
        res.redirect('/login');
    } else{
        const matricula = req.session.matricula;
        req.getConnection((err, conn) => {
            if (err) {
                console.error('Error connecting to the database:', err);
                return res.status(500).send('Database connection error');
            }
    
            conn.query('SELECT matricula, nombre FROM registros WHERE matricula != ?',[matricula], (err, users) => {
                if (err) {
                    console.error('Error fetching users from the database:', err);
                }
                req.session.users = users;
                res.render('principal/subirminuta', {name: req.session.name, users: req.session.users , matricula: req.session.matricula, notifications: req.session.notifications, privateKey: req.session.privateKey});
            });
        });
    } 
}

//Funcion para manejar el renderizado y carga de datos de la pantalla "UPLOAD MEMO"
function uploadm(req, res){
    if(req.session.loggedin != true){
        res.redirect('/login');
    } else{
        const matricula = req.session.matricula;
        req.getConnection((err, conn) => {
            if (err) {
                console.error('Error connecting to the database:', err);
                return res.status(500).send('Database connection error');
            }
    
            conn.query('SELECT matricula, nombre FROM registros WHERE matricula != ?',[matricula], (err, users) => {
                if (err) {
                    console.error('Error fetching users from the database:', err);
                }
                req.session.users = users;
                res.render('principal/subirmemo', {name: req.session.name, matricula: req.session.matricula, notifications: req.session.notifications, users: req.session.users, privateKey: req.session.privateKey});
            });
        });
    } 
}

//Funcion para manejar el renderizado y carga de datos de la pantalla "UPLOAD CONFIDENTIAL MEMO"
function uploadmConfidential(req, res){
    if(req.session.loggedin != true){
        res.redirect('/login');
    } else{
        const matricula = req.session.matricula;
        req.getConnection((err, conn) => {
            if (err) {
                console.error('Error connecting to the database:', err);
                return res.status(500).send('Database connection error');
            }
    
            conn.query('SELECT matricula, nombre FROM registros WHERE matricula != ?',[matricula], (err, users) => {
                if (err) {
                    console.error('Error fetching users from the database:', err);
                }
                req.session.users = users;
                res.render('principal/subirmemoconf', {name: req.session.name, matricula: req.session.matricula, notifications: req.session.notifications, users: req.session.users, privateKey: req.session.privateKey});
            });
        });
    } 
}

//Funcion para manejar el renderizado y carga de datos de la pantalla "View documents"
function verDocumentos(req, res){
    if(req.session.loggedin != true){
        res.redirect('/login');
    } else{
        req.getConnection((err, conn) => {
            if (err) {
                console.error('Error connecting to the database:', err);
                return res.status(500).send('Database connection error');
            }
            //aquí habría que hacer una de las comprobaciones de si ya firmó
            conn.query('SELECT * FROM archivos WHERE recibe = ? OR recibe = "N/A"', [req.session.matricula], (err, results) => {
                if (err) {
                    console.error('Error fetching users from the database:', err);
                }
                const minutas = results.filter(archivo => archivo.tipo === 'Min');
                const memorandos = results.filter(archivo => archivo.tipo === 'Memo');
                const confidentialMemorandos = results.filter(archivo => archivo.tipo === 'Conf');
                //const nombresArchivos = results.map(result => result.name);
                res.render('principal/verDocumentos', {name: req.session.name, minutas, memorandos, confidentialMemorandos, notifications: req.session.notifications, matricula: req.session.matricula, message: req.session.message, privateKey: req.session.privateKey});
            });
        });
    } 
}

//Función llamada con POST desde la pantalla "UPLOAD MINUTE"
function uploadMinut(req, res) {
    const tempUpload = multer({ storage: multer.memoryStorage() }).single('file');

    tempUpload(req, res, function (err) {
        const filePath = path.join(uploadDir, req.file.originalname);

        checkFileExists(filePath)
            .then(exists => {
                if (exists) {
                    if(req.session.loggedin != true){
                        res.redirect('/login');
                    } else{
                        res.render('principal/subirminuta',  {name: req.session.name, users: req.session.users , notifications: req.session.notifications, matricula: req.session.matricula, error: 'File already exists', privateKey: req.session.privateKey});
                    }
                }else{
                    fs.writeFile(filePath, req.file.buffer, (err) => {
                        const data = req.body;
                        const firmasreq = data.users;
                        const firmas = utils.formatNames(firmasreq);
                        const values = [
                            req.file.originalname,
                            data.source,
                            firmas,
                            'N/A',
                            'Min',
                            'N/A',
                            'N/A'
                        ];
    
                        req.getConnection((err, conn) => {
                            if (err) {
                                console.error('Connection error:', err);
                                return res.status(500).json({ error: 'Error de conexión a la base de datos' });
                            }
    
                            conn.query('INSERT INTO archivos (name, envia, firmas, recibe, tipo, kdest, ksource) VALUES (?, ?, ?, ?, ?, ?, ?)', values, (err, result) => {
                                if (err) {
                                    console.error('Query error:', err);
                                    return res.status(500).json({ error: 'Error en la consulta de la base de datos' });
                                }
                                actualizarNotificaciones(req, res, () => {
                                    res.redirect('/firmar');
                                });
                            });
                        });
                    });
                }
                
            })
            .catch(err => {
                console.error('Error al verificar el archivo:', err);
                res.status(500).json({ error: 'Error al verificar el archivo' });
            });
    });
}

//Función llamada con POST desde la pantalla "UPLOAD MEMO"
function uploadMemo(req, res) {
    const tempUpload = multer({ storage: multer.memoryStorage() }).single('file');

    tempUpload(req, res, function (err) {

        const filePath = path.join(uploadDir, req.file.originalname);

        checkFileExists(filePath)
            .then(exists => {
                if (exists) {
                    if(req.session.loggedin != true){
                        res.redirect('/login');
                    } else{
                        res.render('principal/subirmemo',  {name: req.session.name, notifications: req.session.notifications, users: req.session.users, matricula: req.session.matricula, error: 'File already exists', privateKey: req.session.privateKey});
                    }
                }

                fs.writeFile(filePath, req.file.buffer, (err) => {
                    const data = req.body;
                    const firma = utils.formatNames(req.session.matricula);
                    const values = [
                        req.file.originalname,
                        data.source,
                        firma,
                        'N/A',
                        'Memo',
                        'N/A',
                        'N/A'
                    ];
                    req.getConnection((err, conn) => {
                        conn.query('INSERT INTO archivos (name, envia, firmas, recibe, tipo, kdest, ksource) VALUES (?, ?, ?, ?, ?, ?, ?)', values, (err, result) => {
                            if (err) {
                                console.error('Query error:', err);
                                return;
                                }
                            actualizarNotificaciones(req, res, () => {
                                res.redirect('/firmar');
                            });
                        });
                    });
                });
            })
            .catch(err => {
                console.error('Error al verificar el archivo:', err);
                res.status(500).json({ error: 'Error al verificar el archivo' });
            });
    });
}

//Función llamada con POST desde la pantalla "UPLOAD CONFIDENTIAL MEMO"
async function uploadMemoConfidential(req, res) {
    const tempUpload = multer({ storage: multer.memoryStorage() }).single('file');

    tempUpload(req, res, async function (err) {
        if (err) {
            console.error('Error during file upload:', err);
            return res.status(500).json({ error: 'Error during file upload' });
        }

        const filePath = 'src/cifrados/' + req.file.originalname;

        try {
            const exists = await checkFileExists(filePath);
            if (exists) {
                if (req.session.loggedin !== true) {
                    return res.redirect('/login');
                } else {
                    return res.render('principal/subirmemoconf', { name: req.session.name, users: req.session.users, notifications: req.session.notifications, matricula: req.session.matricula, error: 'File already exists', privateKey: req.session.privateKey });
                }
            }

            const data = req.body;
            const receives = data.users;
            const aesKey = crypto.randomBytes(32); //Clave de AES 256 bits
            console.log("AES key Generada: " + aesKey.toString('base64'));

            // Cifrar el archivo con la clave AES
            const { iv, encrypted } = utils.encryptFile(req.file.buffer, aesKey);
            const ivBase64 = iv.toString('base64');
            const encryptedBase64 = encrypted.toString('base64');

            const encryptedData = ivBase64 + ',' + encryptedBase64;

            // Guardar el archivo cifrado
            await fs.promises.writeFile(filePath, encryptedData);

            const encryptedKeys = await Promise.all(receives.map(async (user) => {
                const encryptedKey = await utils.encryptAesKey(req, user, aesKey);
                return {
                    receive: user,
                    encryptedKey: encryptedKey.toString('base64')
                };
            }));

            const firma = utils.formatNames(req.session.matricula);

            try {
                const insertPromises = encryptedKeys.map(({ receive, encryptedKey }) => {
                    let values = [
                        req.file.originalname,
                        data.source,
                        firma,
                        receive,
                        'Conf',
                        encryptedKey,
                        'N/A'
                    ];

                    return new Promise((resolve, reject) => {
                        req.getConnection((err, conn) => {
                            if (err) return reject(err);
                            conn.query('INSERT INTO archivos (name, envia, firmas, recibe, tipo, kdest, ksource) VALUES (?, ?, ?, ?, ?, ?, ?)', values, (err, result) => {
                                if (err) return reject(err);
                                resolve();
                            });
                        });
                    });
                });

                await Promise.all(insertPromises);
                actualizarNotificaciones(req, res, () => {
                    res.redirect('/firmar');
                });
            } catch (err) {
                console.error('Database query error:', err);
                res.status(500).json({ error: 'Database query error' });
            }
        } catch (err) {
            console.error('Error checking file existence:', err);
            res.status(500).json({ error: 'Error checking file existence' });
        }
    });
}

//Función llamada con POST desde la pantalla "SIGN DOCUMENT"
function generatesignature(req, res){
    const data = req.body;
    if(req.session.matricula !== data.user) {
        console.log("Credenciales incorrectas");
        return;
    }

    req.getConnection((err, conn) => { //sacar llave privada
        if (err) {
            console.error('Error de conexión:', err);
            return res.status(500).send('Error de conexión');
        }

        conn.query('SELECT * FROM registros WHERE matricula = ?', [req.session.matricula], (err, datos) => {
            if (err) {
                console.error('Error en la consulta:', err);
                return res.status(500).send('Error en la consulta');
            }

            if (datos.length > 0) {
                const consulta = datos[0];
                if (utils.comparePasswords(data.confcontra, consulta.password)) {
                    const privateKey = utils.obtenerprivkey(req.session.privateKey, req.session.matricula, data.confcontra, true);

                    // Definir dos posibles rutas de archivo
                    const filePath1 = 'src/archivos/' + data.nombreArchivoSeleccionado;
                    const filePath2 = 'src/cifrados/' + data.nombreArchivoSeleccionado;

                    let dataDocument;
                    let filePathToUse;

                    // Intentar leer desde filePath1
                    try {
                        dataDocument = fs.readFileSync(filePath1, 'utf8');
                        filePathToUse = filePath1;
                    } catch (err) {
                        // Si hay error al leer desde filePath1, intentar desde filePath2
                        try {
                            dataDocument = fs.readFileSync(filePath2, 'utf8');
                            filePathToUse = filePath2;
                        } catch (err) {
                            console.error('Error al leer el archivo:', err);
                            return res.status(404).send('Archivo no encontrado en ninguna ubicación');
                        }
                    }

                    const documentHash = utils.calculateHash(dataDocument, 'base64');
                    const signature = utils.signDocument(documentHash, privateKey);

                    const query = 'SELECT firmas FROM archivos WHERE name = ?';
                    const name = [data.nombreArchivoSeleccionado];

                    conn.query(query, name, (err, results) => {
                        if (err) {
                            console.error('Error en la consulta:', err);
                            return res.status(500).send('Error en la consulta');
                        }
                        if (results.length > 0) {
                            let firmas = results[0].firmas;
                            let signedDocument;
                            let filePathPriv;

                            // Definir la ruta de guardado dependiendo de la ruta de lectura usada
                            if (filePathToUse === filePath1) {
                                filePathPriv = 'src/firmas/' + utils.removeExtension(data.nombreArchivoSeleccionado) + '.txt';
                                if (!checkIfFileExists(filePathPriv)) {
                                    signedDocument = `-SIGNATURE-${signature}`;
                                } else {
                                    const dataDocumentSign = fs.readFileSync(filePathPriv, 'utf8');
                                    signedDocument = `${dataDocumentSign}-SIGNATURE-${signature}`;
                                }
                                fs.writeFileSync(filePathPriv, signedDocument, 'utf8');
                                //success
                                firmas = utils.cambiarEstadoMatricula(firmas, req.session.matricula);
                                actualizarBaseNotificaciones(req, res, firmas, data.nombreArchivoSeleccionado, () => {
                                    res.redirect('/principal');
                                });
                            } 
                            else {
                                filePathPriv = 'src/firmasCifradas/' + utils.removeExtension(data.nombreArchivoSeleccionado) + '.txt';
                                
                                conn.query('SELECT kdest FROM archivos WHERE name = ? AND recibe = ?', [data.nombreArchivoSeleccionado, req.session.matricula], (err, destino) => {
                                    if (err) {
                                        console.error("Error al ejecutar la consulta:", err);
                                        return;
                                    }
                            
                                    const aesKeyC = destino[0].kdest;
                                    const aesKey = utils.decryptAesKey(aesKeyC, privateKey);
                                    console.log('Llave de AES: '+aesKey);

                                    if (!checkIfFileExists(filePathPriv)) {
                                        signedDocument = `-SIGNATURE-${signature}`;
                                        const signedBuffer = Buffer.from(signedDocument, 'utf8');
                                        const {iv, encrypted} = utils.encryptFile(signedBuffer, Buffer.from(aesKey,'base64'));
                                        const ivBase64 = iv.toString('base64');
                                        const encryptedBase64 = encrypted.toString('base64');
                                        const encryptedData = ivBase64 + ',' + encryptedBase64;
                                        fs.writeFileSync(filePathPriv, encryptedData, 'utf8');
                                        firmas = utils.cambiarEstadoMatricula(firmas, req.session.matricula);
                                        actualizarBaseNotificaciones(req, res, firmas, data.nombreArchivoSeleccionado, () => { //ERROR
                                            res.redirect('/principal');
                                        });
                                    } else {
                                        const signDataBuffer = fs.readFileSync(filePathPriv, 'utf8');
                                        const signData = signDataBuffer.toString('utf8')
                                        const [ivB64, encryptedB64] = signData.split(',');
                                        const ivBuffer = Buffer.from(ivB64, 'base64');
                                        const encryptedBuffer = Buffer.from(encryptedB64, 'base64');
                                        try {
                                            const decryptedBuffer = utils.decryptFile(ivBuffer, encryptedBuffer, aesKey);
                                            const decryptedData = decryptedBuffer.toString('utf8');
                                            console.log("Decryted data: " + decryptedData);
                                            signedDocument = `${decryptedData}-SIGNATURE-${signature}`;
                                            const signedBuffer = Buffer.from(signedDocument, 'utf8');
                                            const {iv, encrypted} = utils.encryptFile(signedBuffer, Buffer.from(aesKey,'base64'));
                                            const ivBase64 = iv.toString('base64');
                                            const encryptedBase64 = encrypted.toString('base64');
                                            const encryptedData = ivBase64 + ',' + encryptedBase64;
                                            fs.writeFileSync(filePathPriv, encryptedData, 'utf8');
                                            firmas = utils.cambiarEstadoMatricula(firmas, req.session.matricula); 
                                        } catch (error) {
                                            console.error("Error al descifrar los datos:", error);
                                        }
                                        actualizarBaseNotificaciones(req, res, firmas, data.nombreArchivoSeleccionado, () => {//ERROR
                                            res.redirect('/principal');
                                        });
                                    }   
                                });
                            }
                        } else {
                            console.log('No se encontraron resultados.');
                            res.redirect('/principal');
                        }
                    });

                } else {
                    res.render('principal/firmar', {error: '* ERROR. Incorrect Password. Try again', name: req.session.name, notifications: req.session.notifications, matricula: req.session.matricula, privateKey: req.session.privateKey});
                }
            } else {
                console.log("No se encontraron datos para la matrícula especificada.");
                res.redirect('/principal');
            }
        });
    });
}


//Función para descargar el archivo de clave privada
function descargaclave(req, res){
    const protectKeyResult = req.session.protectKey;

    if (!protectKeyResult) {
        return res.status(404).send('Archivo no encontrado');
    }

    // Crear un stream de memoria para almacenar la cadena de texto
    const stream = new MemoryStream();
    stream.write(protectKeyResult);
    stream.end();

    // Configurar la respuesta HTTP para descargar el archivo
    const filename = `${req.session.matricula}_key.bin`;
    res.setHeader('Content-disposition', `attachment; filename=${filename}`);
    res.setHeader('Content-type', 'text/plain');

    // Pipe el contenido del stream de memoria a la respuesta HTTP
    stream.pipe(res);
}

//Función que se manda a llamar desde la pantalla ver documentos para comprobar las firmas
async function pruebafirm(req, res) {
    try {
        const nombreOriginal = req.body.nombreArchivo;
        let nombreDocumento;
        if (nombreOriginal.startsWith('temp_')) { //para cuando generamos los archivos descifrados.
            nombreDocumento = nombreOriginal.substring(5);
        }else{
            nombreDocumento = nombreOriginal;
        }

        const filePath1 = 'src/archivos/' + nombreDocumento;
        const filePath2 = 'src/cifrados/' + nombreDocumento;

        let dataDocument;
        let dataFirmas;
        let filePathToUse;

        // Intentar leer desde filePath1
        try {
            dataDocument = fs.readFileSync(filePath1, 'utf8');
            filePathToUse = filePath1;
        } catch (err) {
            // Si hay error al leer desde filePath1, intentar desde filePath2
            dataDocument = fs.readFileSync(filePath2, 'utf8');
            filePathToUse = filePath2;
        }

        // Obtener conexión
        const conn = await new Promise((resolve, reject) => {
            req.getConnection((err, connection) => {
                if (err) reject(err);
                resolve(connection);
            });
        });

        // Realizar consulta para ver las firmas del documento actual
        const results = await new Promise((resolve, reject) => {
            conn.query('SELECT firmas FROM archivos WHERE name = ?', [nombreDocumento], (err, results) => {
                if (err) reject(err);
                resolve(results);
            });
        });

        // Si acasi algo sale mal con la consulta anterior
        if (results.length === 0) {
            console.log('No se encontraron resultados.');
            return res.redirect('/principal');
        }

        //separa el arreglo de las firmas
        const firmasArray = results[0].firmas.split(',');

        // Verificar si al menos uno ha firmado, sino que no haga todo lo demás
        const hayFirmas = firmasArray.some(firma => firma.trim().split(':')[1].trim() === 'si');
        let message;
        let dataerror;
        if (!hayFirmas) {
            message = `The necessary signatures have not yet been completed for: ${nombreDocumento}`;
            if ((nombreOriginal).startsWith('temp_')) { //para cuando generamos los archivos descifrados.
                nombreDocumento = nombreOriginal; //originalmente estabamos viendo un archivo cifrado
            }
            return res.json({
                success: true,
                message: 'recibido correctamente',
                data: {
                    nombreDocumento: nombreDocumento,
                    additionalInfo: {
                        dato1: message,
                        dato2: dataerror
                    }
                }
            });
        }

        let filePathPriv;

        // Definir la ruta de lectura de firmas dependiendo de la ruta de lectura del doc usada
        if (filePathToUse === filePath1) {
            filePathPriv = 'src/firmas/' + utils.removeExtension(nombreDocumento) + '.txt';
            dataFirmas = fs.readFileSync(filePathPriv, 'utf8');
        } else {
            filePathPriv = 'src/firmasCifradas/' + utils.removeExtension(nombreDocumento) + '.txt';

            const datos = await new Promise((resolve, reject) => {
                conn.query('SELECT * FROM registros WHERE matricula = ?', [req.session.matricula], (err, datos) => {
                    if (err) reject(err);
                    resolve(datos[0]);
                });
            });

            console.log('SE OBTIENEN LOS DATOS DEL USUARIO DE LA SESION');
            const res = await new Promise((resolve, reject) => {
                conn.query('SELECT * FROM archivos WHERE recibe = ? AND name = ?', [req.session.matricula, nombreDocumento], (err, res) => {
                    if (err) reject(err);
                    resolve(res);
                });
            });

            const aesKeyC = res[0].kdest;
            const privateKey = utils.obtenerprivkey(req.session.privateKey, req.session.matricula, datos.password, false);
            const aesKey = utils.decryptAesKey(aesKeyC, privateKey);
            dataFirmas = fs.readFileSync(filePathPriv, 'utf8');
            const signData = dataFirmas.toString('utf8');
            const [ivB64, encryptedB64] = signData.split(',');
            const ivBuffer = Buffer.from(ivB64, 'base64');
            const encryptedBuffer = Buffer.from(encryptedB64, 'base64');
            const decryptedBuffer = utils.decryptFile(ivBuffer, encryptedBuffer, aesKey);
            dataFirmas = decryptedBuffer.toString('utf8');
        }

        let firmasValidas = true;
        const dataFirmasArray = dataFirmas.split('-SIGNATURE-');
        dataFirmasArray.shift();

        const verificarFirmas = firmasArray.map(async firma => {
            const [matricula, status] = firma.trim().split(':');
            if (status.trim() === 'si') {
                const consulta = await new Promise((resolve, reject) => {
                    conn.query('SELECT firma FROM registros WHERE matricula = ?', [matricula], (err, consulta) => {
                        if (err) reject(err);
                        resolve(consulta[0]);
                    });
                });
                const publicKey = consulta.firma;
                if (!verifySignedDocument(dataDocument, dataFirmasArray, publicKey)) {
                    firmasValidas = false;
                }
            }
        });

        await Promise.all(verificarFirmas);
        
        if (firmasValidas) {
            message = `Signatures for: ${nombreDocumento} verified. Document intact.`;
        } else {
            dataerror = `*WARNING! Signatures for: ${nombreDocumento} incorrect. Document corrupted.`;
        }
        if (nombreOriginal.startsWith('temp_')) { //para cuando generamos los archivos descifrados.
            nombreDocumento = nombreOriginal;
        }
        res.json({
            success: true,
            message: 'respuesta correcta',
            data: {
                nombreDocumento: nombreDocumento,
                additionalInfo: {
                    dato1: message,
                    dato2: dataerror
                }
            }
        });
    } catch (error) {
        console.error('Error en la función pruebafirm:', error);
        res.status(500).send('Error en la función pruebafirm');
    }
}



module.exports = {
    principal,
    generatesignature,
    uploadf,
    uploadMinut,
    firmar,
    uploadMemo,
    uploadm,
    uploadmConfidential,
    uploadMemoConfidential,
    alerta,
    descargaclave,
    verDocumentos,
    pruebafirm
}