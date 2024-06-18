
function mostrarConfirmacion() {
    document.getElementById('mensajeConfirmacion').classList.remove('d-none');
    return false;
}

function firmarDocumento(req, res) {
    var user = document.getElementById('user').value;
    var password = document.getElementById('confcontra').value;
    var documentName = document.getElementById('nombreArchivoSeleccionado').textContent;

    console.log("Employee ID: " + user);
    console.log("Password: " + password);
    console.log(documentName);
}

function cancelarFirma() {
    document.getElementById('mensajeConfirmacion').classList.add('d-none');
}

function mostrarFormulario(elemento) {
    var nombreArchivo = elemento.textContent;
    document.getElementById('nombreArchivoSeleccionado').textContent = "Documento a firmar: " + nombreArchivo;
    document.getElementById('formContainer').style.display = 'block';
}
