const crypto = require('crypto');
const cryptJS = require('crypto-js');
const NodeRSA = require('node-rsa');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

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

const upload = multer({ storage }).single('file');;

function principal(req, res){
    if(req.session.loggedin != true){
        res.redirect('/login');
    } else{
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
                enviaValue.push(objeto);
                break; 
            }
        }
    }
    return enviaValue;
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
        res.render('principal/firmar', { name: req.session.name, notifications: req.session.notifications});
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
    
                res.render('principal/subirminuta', {name: req.session.name, users , matricula: req.session.matricula, notifications: req.session.notifications});
            });
        });
    } 
}

function uploadm(req, res){
    if(req.session.loggedin != true){
        res.redirect('/login');
    } else{
        res.render('principal/subirmemo', {name: req.session.name, matricula: req.session.matricula, notifications: req.session.notifications});
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

function uploadMinut(req, res){
    upload(req, res, function (err) {
        if (err) {
        console.log('Error al subir el archivo');
        }
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
            conn.query('INSERT INTO archivos (name, envia, firmas, recibe, tipo) VALUES (?, ?, ?, ?, ?)', values, (err, result) => {
                if (err) {
                    console.error('Query error:', err);
                    return;
                    }
                    res.redirect('/principal');
            });
        });
    });
}

function uploadMemo(req, res){
    upload(req, res, function (err) {
        if (err) {
        console.log('Error al subir el archivo');
        }
        const data = req.body;
        const firmas = formatNames(data.source);
        const values = [
            req.file.originalname,
            data.source,
            firmas,
            data.destiny,
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
    
    req.getConnection((err, conn) => { //sacar llave privada
        conn.query('SELECT * FROM private WHERE usuario = ?', [usr], (err, datos) => {
            if(datos.length > 0) {
                const consulta = datos[0];
                if(comparePasswords(data.confcontra, consulta.password)){
                    const privateKey = addPemHeaders(consulta.key, 'PRIVATE');
                    const documentHash = calculateHash(data.prueba);
                    const signature = signDocument(documentHash, privateKey);
                    const signedDocument = `${data.prueba}\n\n-----BEGIN SIGNATURE-----\n${signature}\n-----END SIGNATURE-----`;
                    console.log(signedDocument);
                    res.redirect('/principal');
                }else{
                    console.log("Contraseña incorrecta");
                }
            }else{
                console.log("no hay nada");
            }
        });
    });
    
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
    generateaes
}