// utils.js
const crypto = require('crypto');
const fs = require('fs');

class Utils {
    constructor() {
        // Puedes inicializar propiedades si es necesario
    }
    
    obtenerprivkey(privateKey, matricula, password, boo){
        const usr = hashPassword(matricula);
        let pss;
        if(boo){
            pss = hashPassword(password);
        }else{
            pss = password;
        }
        const key = XOR_hex(usr,pss);
        const keyBuffer = Buffer.from(key, 'hex');
        const [iv, textoc] = splitString(privateKey.toString());
        const ivbuff = Buffer.from(iv, 'base64');
        const descifrado = decrypt(textoc, keyBuffer, ivbuff);
        return addPemHeaders(descifrado, 'PRIVATE');
    }
}

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

function addPemHeaders(base64, type) {
    const header = `-----BEGIN ${type} KEY-----\n`;
    const footer = `\n-----END ${type} KEY-----`;
    const keyPem = header + base64.match(/.{1,64}/g).join('\n') + footer;
    return keyPem;
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
