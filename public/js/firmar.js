function mostrarConfirmacion() {
    document.getElementById('mensajeConfirmacion').classList.remove('d-none');
    var mensaje = document.getElementById('confcontra');
    mensaje.scrollIntoView({ behavior: 'smooth' });
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
    document.getElementById('nombreArchivoSeleccionado').textContent = "Document to sign: " + nombreArchivo;
    document.getElementById('nombreArchivoSeleccionadoInput').value = nombreArchivo;
    document.getElementById('formContainer').style.display = 'block';
}
