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
        const uploadedFileName = req.session.uploadedFileName; // Reemplaza con tu lógica para obtener el nombre del archivo
        res.render('principal/index', { name: req.session.name, uploadedFileName });
    } 
}

function uploadf(req, res){
    if(req.session.loggedin != true){
        res.redirect('/login');
    } else{
        res.render('principal/subirminuta', {name: req.session.name}); //si existe la sesión
    } 
}

function uploadFile(req, res){
    upload(req, res, function (err) {
        if (err) {
            console.log('Error al subir el archivo');
        }
        req.session.uploadedFileName = req.file.originalname;
        res.redirect('/principal');
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
    uploadFile
}