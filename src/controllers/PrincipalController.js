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
            conn.query('SELECT * FROM registros', (err, users) => {
                if (err) {
                    console.error('Error fetching users from the database:', err);
                }
    
                res.render('principal/index', {name: req.session.name, users , matricula: req.session.matricula});
            });
        });
    } 
}

function firmar(req, res){
    if(req.session.loggedin != true){
        res.redirect('/login');
    } else{
        const uploadedFileName = req.session.uploadedFileName; // Reemplaza con tu lógica para obtener el nombre del archivo
        res.render('principal/firmar', { name: req.session.name, uploadedFileName });
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
    
                res.render('principal/subirminuta', {name: req.session.name, users , matricula: req.session.matricula});
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
    
                res.render('principal/subirmemo', {name: req.session.name, users , matricula: req.session.matricula});
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
                    req.session.uploadedFileName = req.file.originalname;
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
        const firmasreq = data.users;
        const firmas = formatNames(firmasreq);
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
                    req.session.uploadedFileName = req.file.originalname;
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


module.exports = {
    principal,
    generatesignature,
    uploadf,
    uploadMinut,
    firmar,
    uploadMemo,
    uploadm
}