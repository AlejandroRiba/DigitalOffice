const fs = require('fs');
const Utils = require('../controllers/Utils'); 
const utils = new Utils();


function crearDocumento(req, res) {
    const { nombreDocumento } = req.body;
    console.log('Nombre del Documento:', nombreDocumento);
    const tempFileName = 'temp_' + nombreDocumento;
    console.log('Nombre del Documento:', tempFileName);
    const filePathPriv = 'src/cifrados/' + nombreDocumento;
    const filePath = 'src/archivos/' + tempFileName;
    try {
        req.getConnection((err, conn) => {
            conn.query('SELECT kdest FROM archivos WHERE name = ? AND recibe = ?', [nombreDocumento, req.session.matricula], (err, res) => {
                if (err) {
                    console.error("Error al ejecutar la consulta:", err);
                    return;
                }
                const aesKeyC = res[0].kdest;
                conn.query('SELECT * FROM registros WHERE matricula = ?', [req.session.matricula], (err, datos) => {
                    if (err) {
                        console.error('Error en la consulta:', err);
                        return res.status(500).send('Error en la consulta');
                    }
                    const consulta = datos[0];
                    const privateKey = utils.obtenerprivkey(req.session.privateKey, req.session.matricula, consulta.password);
                    // console.log("Matricula: " + req.session.matricula);
                    // console.log("Session PrivateKey: ", req.session.privateKey);
                    // console.log("Private key: " + privateKey);
                    // console.log("AES key: " + aesKeyC)
                    const aesKey = utils.decryptAesKey(aesKeyC, privateKey);
                    const documento = fs.readFileSync(filePathPriv, 'utf8');
                    const signData = documento.toString('utf8')
                    const [ivB64, encryptedB64] = signData.split(',');
                    const ivBuffer = Buffer.from(ivB64, 'base64');
                    const encryptedBuffer = Buffer.from(encryptedB64, 'base64');
                    const decryptedBuffer = utils.decryptFile(ivBuffer, encryptedBuffer, aesKey);
                    const decryptedData = decryptedBuffer;
                    fs.writeFileSync(filePath, decryptedData);
                    
                }); 
            });
        });
        res.json({
            success: true,
            message: 'Datos recibidos correctamente',
            data: {
                nombreDocumento: tempFileName,
                additionalInfo: 'Esta es información adicional de ejemplo'
            }
        });
    } catch (err) {
        console.error('Error al leer el archivo de firmas:', err);
        return res.status(404).send('Archivo de firmas no encontrado');
    }
}

module.exports = {
    crearDocumento,
}