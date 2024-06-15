const crypto = require('crypto');
const cryptJS = require('crypto-js');
const NodeRSA = require('node-rsa');

function principal(req, res){
    if(req.session.loggedin != true){
        res.redirect('/login');
    } else{
        res.render('principal/index', {name: req.session.name}); //si existe la sesión
    } 
}

function generateUniqueKeyPair() {
    const { publicKey, privateKey} = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    return { publicKey, privateKey };
}

function pemToHex(pem) {
    // Remover encabezados y retornos de línea
    const base64 = pem.replace(/-----BEGIN .* KEY-----/, '')
                     .replace(/-----END .* KEY-----/, '')
                     .replace(/\r\n/g, '');

    // Decodificar base64
    const buffer = Buffer.from(base64, 'base64');

    // Convertir a hexadecimal
    const hex = buffer.toString('hex').toUpperCase();

    return hex;
}

function calculateHash(data) {
    const hash = crypto.createHash('sha256');
    hash.update(data);
    return hash.digest('base64');
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

function generatekey(req, res){
    const data = req.body;
    const { publicKey, privateKey } = generateUniqueKeyPair();
    req.getConnection((err, conn) => {
        conn.query('SELECT * FROM registros WHERE firma = ?', [publicKey], (err, datos) => {
            if(datos.length > 0) {
                generatekey(req, res);
            }
            });
    });
   
    const documentHash = calculateHash(data.prueba);
    const signature = signDocument(documentHash, privateKey);
    const signedDocument = `${data.prueba}\n\n-----BEGIN SIGNATURE-----\n${signature}\n-----END SIGNATURE-----`;
    console.log(signedDocument);

    const isSignatureValid = verifySignedDocument(signedDocument, publicKey);

    if (isSignatureValid) {
        console.log('La firma digital es válida.');
    } else {
        console.log('La firma digital no es válida.');
    }
    res.render('principal/index', {
        signed: signedDocument, name: req.session.name
    });
}


module.exports = {
    principal,
    generatekey,
}