function mostrarConfirmacion() {
    document.getElementById('mensajeConfirmacion').classList.remove('d-none');
    return false;
}

function firmarDocumento(req, res) {
    document.querySelector('form').submit();
}

function cancelarFirma() {
    document.getElementById('mensajeConfirmacion').classList.add('d-none');
}

function mostrarFormulario(elemento) {
    var nombreArchivo = elemento.textContent;
    console.log(elemento)
    document.getElementById('nombreArchivoSeleccionado').textContent = "Documento a firmar: " + nombreArchivo;
    document.getElementById('nombreArchivoSeleccionadoInput').value = nombreArchivo;
    document.getElementById('formContainer').style.display = 'block';
}
