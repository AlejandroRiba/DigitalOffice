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

if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
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
                res.render('principal/index', {name: req.session.name, notifications: req.session.notifications, matricula: req.session.matricula});
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
                res.render('principal/visualizar', {name: req.session.name, minutas, memorandos , matricula: req.session.matricula, notifications: req.session.notifications});
            });
        });
    } 
}

function firmar(req, res){
    if(req.session.loggedin != true){
        res.redirect('/login');
    } else{
        res.render('principal/firmar', { name: req.session.name, notifications: req.session.notifications, matricula: req.session.matricula});
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
                res.render('principal/subirminuta', {name: req.session.name, users: req.session.users , matricula: req.session.matricula, notifications: req.session.notifications});
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
                res.render('principal/subirmemo', {name: req.session.name, matricula: req.session.matricula, notifications: req.session.notifications, users: req.session.users});
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
                        res.render('principal/subirminuta',  {name: req.session.name, users: req.session.users , notifications: req.session.notifications, matricula: req.session.matricula, error: 'File already exists' });
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
                            'Min'
                        ];
    
                        req.getConnection((err, conn) => {
                            if (err) {
                                console.error('Connection error:', err);
                                return res.status(500).json({ error: 'Error de conexión a la base de datos' });
                            }
    
                            conn.query('INSERT INTO archivos (name, envia, firmas, recibe, tipo) VALUES (?, ?, ?, ?, ?)', values, (err, result) => {
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
                        res.render('principal/subirmemo',  {name: req.session.name, notifications: req.session.notifications, matricula: req.session.matricula, error: 'File already exists' });
                    }
                }

                fs.writeFile(filePath, req.file.buffer, (err) => {
                    const data = req.body;
                    const receives = data.users;
                    console.log("Receives: ", receives)
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
                        'Memo'
                    ];
                    req.getConnection((err, conn) => {
                        conn.query('INSERT INTO archivos (name, envia, firmas, recibe, tipo) VALUES (?, ?, ?, ?, ?)', values, (err, result) => {
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
                res.render('principal/subirmemoconf', {name: req.session.name, matricula: req.session.matricula, notifications: req.session.notifications, users: req.session.users});
            });
        });
    } 
}

function uploadMemoConfidential(req, res) {
    const tempUpload = multer({ storage: multer.memoryStorage() }).single('file');

    tempUpload(req, res, function (err) {
        if (err) {
            console.error('Error during file upload:', err);
            return res.status(500).json({ error: 'Error during file upload' });
        }

        const filePath = 'src/cifrados/' + req.file.originalname;

        checkFileExists(filePath)
            .then(exists => {
                if (exists) {
                    if (req.session.loggedin != true) {
                        return res.redirect('/login');
                    } else {
                        return res.render('principal/subirmemoconf', { name: req.session.name, notifications: req.session.notifications, matricula: req.session.matricula, error: 'File already exists' });
                    }
                }

                //*************************************/
                //*************************************/
                //*************************************/
                // Aqui hace falta cifrar el archivo xd
                //*************************************/ 
                //*************************************/ 
                //*************************************/ 

                fs.writeFile(filePath, req.file.buffer, (err) => {
                    if (err) {
                        console.error('Error writing file:', err);
                        return res.status(500).json({ error: 'Error writing file' });
                    }

                    const data = req.body;
                    const receives = data.users;
                    const firma = formatNames(req.session.matricula);

                    let insertPromises = receives.map(receive => {
                        let values = [
                            req.file.originalname,
                            data.source,
                            firma,
                            receive,
                            'Conf'
                        ];

                        return new Promise((resolve, reject) => {
                            req.getConnection((err, conn) => {
                                if (err) {
                                    return reject(err);
                                }
                                conn.query('INSERT INTO archivos (name, envia, firmas, recibe, tipo) VALUES (?, ?, ?, ?, ?)', values, (err, result) => {
                                    if (err) {
                                        return reject(err);
                                    }
                                    resolve();
                                });
                            });
                        });
                    });

                    Promise.all(insertPromises)
                        .then(() => {
                            res.redirect('/principal');
                        })
                        .catch(err => {
                            console.error('Database query error:', err);
                            res.status(500).json({ error: 'Database query error' });
                        });
                });
            })
            .catch(err => {
                console.error('Error checking file existence:', err);
                res.status(500).json({ error: 'Error checking file existence' });
            });
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
            conn.query('SELECT name FROM archivos WHERE recibe = ? OR recibe = "N/A"', req.session.matricula, (err, results) => {
                if (err) {
                    console.error('Error fetching users from the database:', err);
                }
                const nombresArchivos = results.map(result => result.name);
                res.render('principal/verDocumentos', {name: req.session.name, notifications: req.session.notifications, matricula: req.session.matricula, documents: nombresArchivos});
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

function generatesignature(req, res){
    const data = req.body;
    const usr = hashPassword(data.user);
    if(req.session.matricula !== data.user)
        console.log("Credenciales incorrectas");
    else{
        req.getConnection((err, conn) => { //sacar llave privada
            conn.query('SELECT * FROM private WHERE usuario = ?', [usr], (err, datos) => {
                if(datos.length > 0) {
                    const consulta = datos[0];
                    if(comparePasswords(data.confcontra, consulta.password)){
                        const privateKey = addPemHeaders(consulta.key, 'PRIVATE');
                        const filePath = 'src/archivos/' + data.nombreArchivoSeleccionado;
                        const filePathPriv = 'src/firmas/' + removeExtension(data.nombreArchivoSeleccionado) + '.txt';
                        const dataDocument = fs.readFileSync(filePath, 'utf8');
                        const documentHash = calculateHash(dataDocument);
                        const signature = signDocument(documentHash, privateKey);
                        var signedDocument;
                        if(!checkIfFileExists(filePathPriv)){
                            signedDocument = `-SIGNATURE-${signature}`;
                        }
                        else{
                            const dataDocumentSign = fs.readFileSync(filePathPriv, 'utf8');
                            signedDocument = `${dataDocumentSign}-SIGNATURE-${signature}`;
                        }
                        fs.writeFileSync(filePathPriv, signedDocument,'utf8')

                        const query = 'SELECT firmas FROM archivos WHERE name = ?'
                        const name = [data.nombreArchivoSeleccionado]
                        conn.query(query, name, (err, results) => {
                            if (err) {
                                console.error('Error en la consulta:', err);
                                return;
                            }
                            
                            if (results.length > 0) {
                                var firmas = results[0].firmas;
                                firmas = cambiarEstadoMatricula(firmas, req.session.matricula)
                                const queryUpdate = 'UPDATE archivos SET firmas = ? WHERE name = ?'
                                const firmasModificadas = [firmas,data.nombreArchivoSeleccionado]

                                conn.query(queryUpdate, firmasModificadas, (err, result) => {                              
                                    if (err) {
                                      console.error("Error al actualizar el campo", err);
                                      return res.status(500).send('Error al actualizar el campo');
                                    }
                              
                                    if (result.affectedRows === 0) {
                                      return res.status(404).send('Entrada no encontrada');
                                    }
                              
                                    req.session.notifications = actualizarNotificaciones(req, res);
                                });

                            } else {
                                console.log('No se encontraron resultados.');
                            }
                        });
                        res.redirect('/principal');
                    }else{
                        res.render('principal/firmar', {error: '* ERROR. Incorrect password.', name: req.session.name, notifications: req.session.notifications, matricula: req.session.matricula});
                    }
                }else{
                    console.log("no hay nada");
                }
            });
        });
    }
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
            console.log(notifications);
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
    verDocumentos
}