const crypto = require('crypto');
const cryptJS = require('crypto-js');
const NodeRSA = require('node-rsa');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const MemoryStream = require('memorystream');
const Utils = require('../controllers/Utils'); 
const utils = new Utils();

function hashPassword(password) {
    const hash = crypto.createHash('sha256')
                       .update(password)
                       .digest('hex');
    return hash;
}

function decrypt(encryptedHex, keyBuffer, ivBuffer) {
    const decipher = crypto.createDecipheriv('aes-256-ctr', keyBuffer, ivBuffer);
    let decrypted = decipher.update(encryptedHex, 'base64', 'base64');
    decrypted += decipher.final('base64');
    return decrypted;
}


async function encryptAesKey(req, receive, key) {
    return new Promise((resolve, reject) => {
        req.getConnection((err, conn) => {
            if (err) return reject(err);
            conn.query('SELECT firma FROM registros WHERE matricula = ?', [receive], (err, result) => {
                if (err) return reject(err);
                if (!result.length) return reject(new Error('No se encontró el registro'));

                const publicKeyDest = result[0].firma;
                console.log(publicKeyDest); // Debe ser en formato PEM o DER

                try {
                    const encryptedKey = encryptWithPublicKey(publicKeyDest, key);
                    resolve(encryptedKey);
                } catch (error) {
                    reject(new Error('Failed to encrypt key: ' + error.message));
                }
            });
        });
    });
}

function decryptFile(iv, encrypted, aesKey64) {
    const aesKey = Buffer.from(aesKey64, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-ctr', aesKey, iv);
    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted;
}

function encryptWithPublicKey(publicKey, aesKey) {
    const buffer = Buffer.from(aesKey, 'utf8');
    const encryptedKey = crypto.publicEncrypt(
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, // Asegúrate de usar el acolchado correcto
        oaepHash: 'sha256', // Si usas acolchado OAEP
      },
      buffer
    );
    return encryptedKey.toString('base64');
}

function decryptAesKey(encryptedAesKey, privateKey) {
    try {
      const buffer = Buffer.from(encryptedAesKey, 'base64');
      const decryptedKey = crypto.privateDecrypt(
        {
          key: privateKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, // Asegúrate de usar el acolchado correcto
          oaepHash: 'sha256', // Si usas acolchado OAEP
        },
        buffer
      );
      return decryptedKey.toString('base64');
    } catch (error) {
      console.error('Fallo en el descifrado:', error);
      throw error; // Maneja el error adecuadamente
    }
}

function crearDocumento(req, res) {
    const { nombreDocumento } = req.body;
    console.log('Nombre del Documento:', nombreDocumento);
    filePathPriv = 'src/cifrados/' + nombreDocumento;
    filePath = 'src/archivos/' + nombreDocumento;
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
                    const aesKey = decryptAesKey(aesKeyC, privateKey);
                    const documento = fs.readFileSync(filePathPriv, 'utf8');
                    const signData = documento.toString('utf8')
                    const [ivB64, encryptedB64] = signData.split(',');
                    const ivBuffer = Buffer.from(ivB64, 'base64');
                    const encryptedBuffer = Buffer.from(encryptedB64, 'base64');
                    const decryptedBuffer = decryptFile(ivBuffer, encryptedBuffer, aesKey);
                    const decryptedData = decryptedBuffer;
                    fs.writeFileSync(filePath, decryptedData);
                    
                }); 
            });
        });
        res.json({
            success: true,
            message: 'Datos recibidos correctamente',
            data: {
                nombreDocumento: nombreDocumento,
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