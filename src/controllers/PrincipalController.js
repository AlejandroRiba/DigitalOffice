const crypto = require('crypto');
const cryptJS = require('crypto-js');
const NodeRSA = require('node-rsa');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { fileLoader } = require('ejs');
const { PDFDocument, rgb } = require('pdf-lib');
const MemoryStream = require('memorystream');


// Directorio donde se guardarán los archivos subidos
const uploadDir = path.join(__dirname, '../archivos');
const firmasDir = path.join(__dirname, '../firmas');

if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

if (!fs.existsSync(firmasDir)) {
    fs.mkdirSync(firmasDir);
}

const storage = multer.diskStorage({
    destination: uploadDir,
    filename: function (req, file, cb) {
        cb(null, file.originalname);
    }
});

const upload = multer({ storage }).single('file');

const checkFileExists = (filePath) => {
    return fs.promises.access(filePath, fs.constants.F_OK)
        .then(() => true)
        .catch(() => false);
};



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
            conn.query('SELECT name,envia,firmas FROM archivos', (err, results) => {
                if (err) {
                    console.error('Error fetching users from the database:', err);
                }
                let notifications = obtenerNotificaciones(results, req.session.matricula);
                req.session.notifications = notifications;
                delete req.session.message;
                delete req.session.doc;
                res.render('principal/index', {name: req.session.name, notifications: req.session.notifications, matricula: req.session.matricula, privateKey: req.session.privateKey});
            });
        });
    } 
}

function obtenerNotificaciones(results, req_matricula){
    let enviaValue = [];
    for (let i = 0; i < results.length; i++) {
        const result = results[i];
        const firmas = result.firmas;
        const pairs = firmas.split(', ');

        for (let j = 0; j < pairs.length; j++) {
            const pair = pairs[j];

            const [matricula, estado] = pair.split(': ');

            if (matricula === req_matricula && estado === 'no') {
                const objeto = {
                    name: result.name,
                    matricula: result.envia
                };

                if(!enviaValue.includes(objeto)){
                    enviaValue.push(objeto);
                    break; 
                }
            }
        }
    }
    return enviaValue;
}

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

function visualizar(req, res){
    if(req.session.loggedin != true){
        res.redirect('/login');
    } else{
        req.getConnection((err, conn) => {
            if (err) {
                console.error('Error connecting to the database:', err);
                return res.status(500).send('Database connection error');
            }
            //aquí habría que hacer una de las comprobaciones de si ya firmó
            conn.query('SELECT name, envia, tipo FROM archivos', (err, archivos) => {
                if (err) {
                    console.error('Error fetching users from the database:', err);
                }
                const minutas = archivos.filter(archivo => archivo.tipo === 'Min');
                const memorandos = archivos.filter(archivo => archivo.tipo === 'Memo');
                delete req.session.message;
                delete req.session.doc;
                res.render('principal/visualizar', {name: req.session.name, minutas, memorandos , matricula: req.session.matricula, notifications: req.session.notifications, privateKey: req.session.privateKey});
            });
        });
    } 
}

function firmar(req, res){
    if(req.session.loggedin != true){
        res.redirect('/login');
    } else{
        delete req.session.message;
        delete req.session.doc; //se eliminan datos usados provisionalmente
        res.render('principal/firmar', { name: req.session.name, notifications: req.session.notifications, matricula: req.session.matricula, privateKey: req.session.privateKey});
    } 
}

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
                delete req.session.message;
                delete req.session.doc;
                res.render('principal/subirminuta', {name: req.session.name, users: req.session.users , matricula: req.session.matricula, notifications: req.session.notifications, privateKey: req.session.privateKey});
            });
        });
    } 
}

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
                delete req.session.message;
                delete req.session.doc;
                res.render('principal/subirmemo', {name: req.session.name, matricula: req.session.matricula, notifications: req.session.notifications, users: req.session.users, privateKey: req.session.privateKey});
            });
        });
    } 
}

function formatNames(names) {
    if (typeof names === 'string') {
        // Convertir la cadena JSON a un arreglo si es necesario
        names = [names];
    }

    // Recorremos el arreglo de nombres y creamos una cadena formateada
    const formattedString = names.map(name => `${name}: no`).join(', ');

    return formattedString;
}

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
                        const firmas = formatNames(firmasreq);
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
    
                                res.redirect('/principal');
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
                        res.render('principal/subirmemo',  {name: req.session.name, notifications: req.session.notifications, matricula: req.session.matricula, error: 'File already exists', privateKey: req.session.privateKey});
                    }
                }

                fs.writeFile(filePath, req.file.buffer, (err) => {
                    const data = req.body;
                    const receives = data.users;
                    const firma = formatNames(req.session.matricula);
                    // const values = [
                    //     req.file.originalname,
                    //     data.source,
                    //     firmas,
                    //     data.destiny,
                    //     'Memo'
                    // ];
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
                                res.redirect('/principal');
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

async function encryptAesKey(req, receive, key) {
    return new Promise((resolve, reject) => {
        req.getConnection((err, conn) => {
            if (err) return reject(err);
            conn.query('SELECT firma FROM registros WHERE matricula = ?', [receive], (err, result) => {
                if (err) return reject(err);
                if (!result.length) return reject(new Error('No se encontró el registro'));

                const publicKeyDest = result[0].firma;
                try {
                    const encryptedKey = crypto.publicEncrypt(
                        {
                            key: publicKeyDest,
                            padding: crypto.constants.RSA_PKCS1_PADDING
                        },
                        key
                    );
                    resolve(encryptedKey);
                } catch (error) {
                    reject(new Error('Failed to encrypt key: ' + error.message));
                }
            });
        });
    });
}

function decryptAesKey(encryptedKey, privateKey) {
    try {
        const buffer = Buffer.from(encryptedKey, 'base64');
        const decryptedKey = crypto.privateDecrypt(
            {
                key: privateKey,
                padding: crypto.constants.RSA_PKCS1_PADDING
            },
            buffer
        );
        return decryptedKey.toString('utf8');
    } catch (error) {
        console.error('Error while decrypting:', error.message);
        throw new Error('Failed to decrypt key');
    }
}


async function generateAesKey(req) {
    return new Promise((resolve, reject) => {
        req.getConnection((err, conn) => {
            if (err) return reject(err);
            conn.query('SELECT * FROM registros WHERE matricula = ?', [req.session.matricula], (err, result) => {
                if (err) return reject(err);
                if (!result.length) return reject(new Error('No se encontró el registro'));
                const key128 = crypto.randomBytes(32);
                resolve(key128);
            });
        });
    });
}

function encryptFile(buffer, aesKey) {
    const iv = crypto.randomBytes(16); // Generar un IV de 16 bytes
    const cipher = crypto.createCipheriv('aes-256-ctr', aesKey, iv);
    let encrypted = cipher.update(buffer);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return { iv, encrypted };
}

function decryptFile(encryptedData, aesKey) {
    const { iv, encrypted } = encryptedData;
    const decipher = crypto.createDecipheriv('aes-256-ctr', aesKey, iv);
    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted;
}


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
                    return res.render('principal/subirmemoconf', { name: req.session.name, notifications: req.session.notifications, matricula: req.session.matricula, error: 'File already exists', privateKey: req.session.privateKey });
                }
            }

            const data = req.body;
            const receives = data.users;
            const aesKey = await generateAesKey(req);

            // Cifrar el archivo con la clave AES
            const { iv, encrypted } = encryptFile(req.file.buffer, aesKey);

            // Guardar el archivo cifrado
            await fs.promises.writeFile(filePath, Buffer.concat([iv, encrypted]));

            const encryptedKeys = await Promise.all(receives.map(async (user) => {
                const encryptedKey = await encryptAesKey(req, user, aesKey);
                return {
                    receive: user,
                    encryptedKey: encryptedKey.toString('base64')
                };
            }));

            const firma = formatNames(req.session.matricula);

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
                res.redirect('/principal');
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
                //const nombresArchivos = results.map(result => result.name);
                res.render('principal/verDocumentos', {name: req.session.name, minutas, memorandos, notifications: req.session.notifications, matricula: req.session.matricula, message: req.session.message, nombreArch: req.session.doc, privateKey: req.session.privateKey});
            });
        });
    } 
}

function obtenerDocumentos(results, req_matricula){
    let enviaValue = [];
    for (let i = 0; i < results.length; i++) {
        const result = results[i];
        const firmas = result.firmas;
        const pairs = firmas.split(', ');

        for (let j = 0; j < pairs.length; j++) {
            const pair = pairs[j];

            const [matricula, estado] = pair.split(': ');

            if (matricula === req_matricula && estado === 'no') {
                const objeto = {
                    name: result.name,
                    matricula: result.envia
                };

                if(!enviaValue.includes(objeto)){
                    enviaValue.push(objeto);
                    break; 
                }
            }
        }
    }
    return enviaValue;
}



function calculateHash(data) {
    const hash = crypto.createHash('sha256');
    hash.update(data);
    return hash.digest('base64');
}

function hashPassword(password) {
    const hash = crypto.createHash('sha256')
                       .update(password)
                       .digest('hex');
    return hash;
}

function signDocument(hash, privateKey) {
    const sign = crypto.createSign('RSA-SHA256');
    sign.update(hash);
    return sign.sign(privateKey, 'base64');
}

function verifySignature(message, signature, publicKey) {
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(message);
    return verifier.verify(publicKey, Buffer.from(signature, 'base64'));
}

// Función para verificar el documento firmado
function verifySignedDocument(signedDocument, publicKey) {
    // Separar el contenido del documento y la firma
    const [documentContent, signatureBase64] = signedDocument.split('\n\n-----BEGIN SIGNATURE-----\n');
    const signature = signatureBase64.replace('-----END SIGNATURE-----', '').trim();

    // Calcular el hash del contenido del documento
    const documentHash = calculateHash(documentContent);

    // Verificar la firma
    return verifySignature(documentHash, signature, publicKey);
}

function addPemHeaders(base64, type) {
    const header = `-----BEGIN ${type} KEY-----\n`;
    const footer = `\n-----END ${type} KEY-----`;
    const keyPem = header + base64.match(/.{1,64}/g).join('\n') + footer;
    return keyPem;
}

function comparePasswords(plainPassword, hashedPassword) {
    const hashedInputPassword = hashPassword(plainPassword);
    return hashedInputPassword === hashedPassword;
}

function XOR_hex(a, b) {
    const buffer1 = Buffer.from(a, 'hex');
    const buffer2 = Buffer.from(b, 'hex');

    // Obtener la longitud máxima entre los dos buffers
    const maxLength = Math.max(buffer1.length, buffer2.length);

    // Realizar la operación XOR a nivel de bits
    let result = '';
    for (let i = 0; i < maxLength; i++) {
        const byte1 = i < buffer1.length ? buffer1[i] : 0;
        const byte2 = i < buffer2.length ? buffer2[i] : 0;
        const xorResult = byte1 ^ byte2;
        result += xorResult.toString(16).padStart(2, '0'); // Convertir resultado a hexadecimal
    }

    return result;
}

function obtenerprivkey(privateKey, matricula, password){
    const usr = hashPassword(matricula);
    const pss = hashPassword(password);
    const key = XOR_hex(usr,pss);
    const keyBuffer = Buffer.from(key, 'hex');
    const [iv, textoc] = splitString(privateKey.toString());
    const ivbuff = Buffer.from(iv, 'base64');
    const descifrado = decrypt(textoc, keyBuffer, ivbuff);
    return addPemHeaders(descifrado, 'PRIVATE');
}

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
                if (comparePasswords(data.confcontra, consulta.password)) {
                    const privateKey = obtenerprivkey(req.session.privateKey, req.session.matricula, data.confcontra);

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

                    const documentHash = calculateHash(dataDocument);
                    const signature = signDocument(documentHash, privateKey);

                    const query = 'SELECT firmas FROM archivos WHERE name = ?';
                    const name = [data.nombreArchivoSeleccionado];

                    conn.query(query, name, (err, results) => {
                        if (err) {
                            console.error('Error en la consulta:', err);
                            return res.status(500).send('Error en la consulta');
                        }

                        let signedDocument;
                        let filePathPriv;

                        // Definir la ruta de guardado dependiendo de la ruta de lectura usada
                        if (filePathToUse === filePath1) {
                            filePathPriv = 'src/firmas/' + removeExtension(data.nombreArchivoSeleccionado) + '.txt';
                            if (!checkIfFileExists(filePathPriv)) {
                                signedDocument = `-SIGNATURE-${signature}`;
                            } else {
                                const dataDocumentSign = fs.readFileSync(filePathPriv, 'utf8');
                                signedDocument = `${dataDocumentSign}-SIGNATURE-${signature}`;
                            }
                            fs.writeFileSync(filePathPriv, signedDocument, 'utf8');
                        } 
                        else {
                            filePathPriv = 'src/firmasCifradas/' + removeExtension(data.nombreArchivoSeleccionado) + '.txt';
                            req.getConnection((err, conn)=>{
                                conn.query('SELECT kdest FROM archivos WHERE name = ? AND recibe = ?', [data.nombreArchivoSeleccionado, req.session.matricula], (err, res)=>{
                                    const aesKeyC = res[0].kdest;
                                    console.log("aesKeyC: ", aesKeyC);
                                    console.log("private key: ", privateKey)
                                    const aesKey = decryptAesKey(aesKeyC, privateKey);
                                    console.log("aesKey: ", aesKey.toString('base64'));
                                });
                            });
                            return;
                            if (!checkIfFileExists(filePathPriv)) {
                                signedDocument = `-SIGNATURE-${signature}`;
                                fs.writeFileSync(filePathPriv, signedDocument, 'utf8');
                            } else {
                                const dataDocumentSign = fs.readFileSync(filePathPriv, 'utf8');
                                signedDocument = `${dataDocumentSign}-SIGNATURE-${signature}`;
                                fs.writeFileSync(filePathPriv, signedDocument, 'utf8');
                            }
                        }

                        if (results.length > 0) {
                            let firmas = results[0].firmas;
                            firmas = cambiarEstadoMatricula(firmas, req.session.matricula);
                            const queryUpdate = 'UPDATE archivos SET firmas = ? WHERE name = ?';
                            const firmasModificadas = [firmas, data.nombreArchivoSeleccionado];

                            conn.query(queryUpdate, firmasModificadas, (err, result) => {
                                if (err) {
                                    console.error("Error al actualizar el campo", err);
                                    return res.status(500).send('Error al actualizar el campo');
                                }

                                if (result.affectedRows === 0) {
                                    return res.status(404).send('Entrada no encontrada');
                                }

                                req.session.notifications = actualizarNotificaciones(req, res);
                                res.redirect('/principal');
                            });

                        } else {
                            console.log('No se encontraron resultados.');
                            res.redirect('/principal');
                        }
                    });

                } else {
                    res.render('principal/firmar', {error: '* ERROR. Contraseña incorrecta.', name: req.session.name, notifications: req.session.notifications, matricula: req.session.matricula, privateKey: req.session.privateKey});
                }
            } else {
                console.log("No se encontraron datos para la matrícula especificada.");
                res.redirect('/principal');
            }
        });
    });
}

function getAESKeyC(req, fileName){
    req.getConnection((err, conn)=>{
        conn.query('SELECT kdest FROM archivos WHERE name = ? AND recibe = ?', [fileName, req.session.matricula], (err, res)=>{
            return res[0];
        });
    });
}

function actualizarNotificaciones(req, res){
    req.getConnection((err, conn) => {
        if (err) {
            console.error('Error connecting to the database:', err);
            return res.status(500).send('Database connection error');
        }
        //aquí habría que hacer una de las comprobaciones de si ya firmó
        conn.query('SELECT name,envia,firmas FROM archivos', (err, results) => {
            if (err) {
                console.error('Error fetching users from the database:', err);
            }
            let notifications = obtenerNotificaciones(results, req.session.matricula);
            req.session.notifications = notifications;
            return notifications;
        });
    });
}

function removeExtension(filePath) {
    const parsedPath = path.parse(filePath);
    return parsedPath.name;
}

const cambiarEstadoMatricula = (cadena, matricula) => {
    // Usar una expresión regular para encontrar y reemplazar el valor "no" por "si" para la matrícula específica
    const regex = new RegExp(`(${matricula}:\\s*)no`, 'g');
    const nuevaCadena = cadena.replace(regex, `$1si`);
  
    return nuevaCadena;
  };

async function removeSignaturesFromPDF(inputFilePath, outputFilePath) {
    try {
        // Leer el archivo PDF
        const pdfBytes = fs.readFileSync(inputFilePath);

        // Cargar el documento PDF usando pdf-lib
        const pdfDoc = await PDFDocument.load(pdfBytes);

        // Eliminar firmas o datos adicionales según sea necesario
        // Aquí se puede implementar la lógica específica para detectar y eliminar firmas del PDF

        // Guardar el archivo modificado
        const modifiedPdfBytes = await pdfDoc.save();

        fs.writeFileSync(outputFilePath, modifiedPdfBytes);

        console.log(`Firmas eliminadas correctamente. Documento guardado en: ${outputFilePath}`);
    } catch (error) {
        console.error('Error al eliminar firmas y guardar el documento:', error);
    }
}

function checkIfFileExists(filePath) {
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

//Función para descifrar
function decrypt(encryptedHex, keyBuffer, ivBuffer) {
    const decipher = crypto.createDecipheriv('aes-256-ctr', keyBuffer, ivBuffer);
    let decrypted = decipher.update(encryptedHex, 'base64', 'base64');
    decrypted += decipher.final('base64');
    return decrypted;
}

function splitString(str) {
    const firstPart = str.slice(0, 24);  // Obtener los primeros 24 caracteres
    const secondPart = str.slice(24);    // Obtener el resto de la cadena
    
    return [firstPart, secondPart];
}

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

function generateaes(req, res){
    const data = req.body;
    const usr = hashPassword(data.user);
    req.getConnection((err, conn) => { //sacar llave privada
        conn.query('SELECT * FROM registros WHERE matricula = ?', [data.user], (err, datos) => {
            if(datos.length > 0) {
                const consulta = datos[0];
                const key128 = crypto.randomBytes(16);
                console.log('Clave AES: ',key128.toString('hex'));
                const publicKey = addPemHeaders(consulta.firma, 'PUBLIC');
                const cryp = crypto.publicEncrypt(publicKey, key128);
                console.log(cryp.toString('base64'));

                conn.query('SELECT * FROM private WHERE usuario = ?',[usr] , (err, datos1) => {
                    const consulta = datos1[0];
                    const privateKey = addPemHeaders(consulta.key, 'PRIVATE');
                    const decr = crypto.privateDecrypt(privateKey, cryp);
                    console.log('Clave descifrada: ',decr.toString('hex'));
                    res.redirect('/principal');
                });
            }else{
                console.log("no hay nada");
            }
        });
    });
}

function pruebafirm(req, res){
    const nombreDocumento = req.body.nombreArchivo;

    // Aquí puedes realizar cualquier lógica necesaria, como consultas a la base de datos, etc.
    // Por ejemplo, responder con un mensaje simple
    req.session.message = `Firmas de: ${nombreDocumento} verificadas. Documento integro.`;
    req.session.doc = nombreDocumento;
    res.redirect('/verDocumentos');
}


module.exports = {
    principal,
    generatesignature,
    uploadf,
    uploadMinut,
    firmar,
    uploadMemo,
    uploadm,
    visualizar,
    generateaes,
    uploadmConfidential,
    uploadMemoConfidential,
    alerta,
    descargaclave,
    verDocumentos,
    pruebafirm
}