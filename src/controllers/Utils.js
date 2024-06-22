// utils.js
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

class Utils {
    constructor() {
        // Puedes inicializar propiedades si es necesario
    }

    addPemHeaders(base64, type) {
        const header = `-----BEGIN ${type} KEY-----\n`;
        const footer = `\n-----END ${type} KEY-----`;
        const keyPem = header + base64.match(/.{1,64}/g).join('\n') + footer;
        return keyPem;
    }

    removePemHeaders(pem) {
        const pemLines = pem.split('\n');
        const base64Lines = pemLines.filter(line => {
            return line && !line.startsWith('-----BEGIN') && !line.startsWith('-----END');
        });
        return base64Lines.join('');
    }

    removeExtension(filePath) {
        const parsedPath = path.parse(filePath);
        return parsedPath.name;
    }

    protectkey(usuario, password, privateKey){
        const usr = this.calculateHash(usuario, 'hex');
        const pss = this.calculateHash(password,'hex');
        const iv = crypto.randomBytes(16);
        const key = XOR_hex(usr,pss);
        const final = this.removePemHeaders(privateKey);
        const keyBuffer = Buffer.from(key, 'hex');
        const encryptedText = encrypt(final, keyBuffer, iv);
        const privtofile = iv.toString('base64') + encryptedText;
        return privtofile;
    }
    
    obtenerprivkey(privateKey, matricula, password, bool){
        const usr = this.calculateHash(matricula,'hex');
        let pss;
        if(bool){
            pss = this.calculateHash(password,'hex');
        }else{
            pss = password;
        }
        const key = XOR_hex(usr,pss);
        const keyBuffer = Buffer.from(key, 'hex');
        const [iv, textoc] = splitString(privateKey.toString());
        const ivbuff = Buffer.from(iv, 'base64');
        const descifrado = decrypt(textoc, keyBuffer, ivbuff);
        return this.addPemHeaders(descifrado, 'PRIVATE');
    }

    comparePasswords(plainPassword, hashedPassword) {
        const hashedInputPassword = this.calculateHash(plainPassword,'hex');
        return hashedInputPassword === hashedPassword;
    }

    encryptFile(buffer, aesKey) {
        const iv = crypto.randomBytes(16); // Generar un IV de 16 bytes
        console.log('iv: ' + iv.toString('base64'));
        const cipher = crypto.createCipheriv('aes-256-ctr', aesKey, iv);
        let encrypted = cipher.update(buffer);
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        return { iv, encrypted };
    }
    
    decryptFile(iv, encrypted, aesKey64) {
        const aesKey = Buffer.from(aesKey64, 'base64');
        const decipher = crypto.createDecipheriv('aes-256-ctr', aesKey, iv);
        let decrypted = decipher.update(encrypted);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted;
    }

    calculateHash(data, encoding) {
        const hash = crypto.createHash('sha256')
                               .update(data)
                               .digest(encoding);
            return hash;
    }

    signDocument(hash, privateKey) {
        const sign = crypto.createSign('RSA-SHA256');
        sign.update(hash);
        return sign.sign(privateKey, 'base64');
    }

    verifySignature(message, signature, publicKey) {
        const verifier = crypto.createVerify('RSA-SHA256');
        verifier.update(message);
        return verifier.verify(publicKey, Buffer.from(signature, 'base64'));
    }

    //recibe un arreglo o un string en caso de ser un solo usuario seleccionado, define el formato para la base
    //de datos en la que se pone matricula: no, matricula: no, etc para indicar que no ha firmado
    formatNames(names) {
        if (typeof names === 'string') {
            // Convertir la cadena JSON a un arreglo si es necesario
            names = [names];
        }
    
        // Recorremos el arreglo de nombres y creamos una cadena formateada
        const formattedString = names.map(name => `${name}: no`).join(', ');
    
        return formattedString;
    }

    //Actualiza cuando ya se firmó un documento
    cambiarEstadoMatricula = (cadena, matricula) => {
        // Usar una expresión regular para encontrar y reemplazar el valor "no" por "si" para la matrícula específica
        const regex = new RegExp(`(${matricula}:\\s*)no`, 'g');
        const nuevaCadena = cadena.replace(regex, `$1si`);
      
        return nuevaCadena;
    };

    //recibe el array de la consulta a la base, para buscar los archivos en los que se requiere la firma del usuario de la sesión
    obtenerNotificaciones(results, req_matricula){
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

    encryptWithPublicKey(publicKey, aesKey) {
        const buffer = Buffer.from(aesKey, 'utf8');
        const encryptedKey = crypto.publicEncrypt(
          {
            key: publicKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, // Padding necesario en la función publicEncrypt por seguridad y compatibilidad
                                                             //garantizar que el cifrado y descifrado funcionen de manera consistente entre diferentes sistemas y plataformas
            oaepHash: 'sha256',
          },
          buffer
        );
        return encryptedKey.toString('base64');
    }

    async encryptAesKey(req, receive, key) {
        return new Promise((resolve, reject) => {
            req.getConnection((err, conn) => {
                if (err) return reject(err);
                conn.query('SELECT firma FROM registros WHERE matricula = ?', [receive], (err, result) => {
                    if (err) return reject(err);
                    if (!result.length) return reject(new Error('No se encontró el registro'));
    
                    const publicKeyDest = result[0].firma;
                    console.log(publicKeyDest); // Debe ser en formato PEM o DER
    
                    try {
                        const encryptedKey = this.encryptWithPublicKey(publicKeyDest, key);
                        resolve(encryptedKey);
                    } catch (error) {
                        reject(new Error('Failed to encrypt key: ' + error.message));
                    }
                });
            });
        });
    }
    
    decryptAesKey(encryptedAesKey, privateKey) {
        try {
          const buffer = Buffer.from(encryptedAesKey, 'base64');
          const decryptedKey = crypto.privateDecrypt(
            {
              key: privateKey,
              padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
              oaepHash: 'sha256',
            },
            buffer
          );
          return decryptedKey.toString('base64');
        } catch (error) {
          console.error('Fallo en el descifrado:', error);
          throw error; // Maneja el error adecuadamente
        }
    }

}

//Para cifrar la privatekey
function encrypt(text, keyBuffer, iv) {
    const cipher = crypto.createCipheriv('aes-256-ctr', keyBuffer, iv);
    let encrypted = cipher.update(text, 'base64', 'base64'); 
    encrypted += cipher.final('base64');
    return encrypted;
}

//para descifrar la privatekey
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

module.exports = Utils;
