document.addEventListener('DOMContentLoaded', function() {
    const urlParams = new URLSearchParams(window.location.search);
    const dato = urlParams.get('dato');
    // Obtener todos los elementos con clase 'documento-item'
    var elementos = document.querySelectorAll('.documento-item');
    // Iterar sobre los elementos para encontrar el que coincide con 'dato'
    var elementoEncontrado = null;
    elementos.forEach(function(elemento) {
        if (elemento.textContent.trim() === dato.trim()) {
            elementoEncontrado = elemento;
            return; // Salir del bucle forEach una vez encontrado el elemento
        }
    });
    if (elementoEncontrado) {
        // Hacer algo con el elemento encontrado
        mostrarFormulario(elementoEncontrado);
    }  
});


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

