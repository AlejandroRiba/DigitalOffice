function validacion_login(){
    var usuario = document.getElementById('usuario').value; //correo o matricula del tipo: (10 caracteres) 4letras6numeros
    var contrasena = document.getElementById('contras').value;

    /* +++++++++++++++++++++++++++++++  VALIDACIÓN PARA EL CORREO ELECTRÓNICO O MATRICULA +++++++++++++++++++++++++++++++ */
    var valUser = /^(?:[^\s@]+@[^\s@]+\.[^\s@]+)|(?:[A-Za-z]{4}\d{6})$/;
    if(!valUser.test(usuario)){
      alert('Usuario no válido.');
      return false;
    }

    return true;
}

function validarUser(input) {
    var valCorreo = /^(?:[^\s@]+@[^\s@]+\.[^\s@]{2,})|(?:[A-Za-z]{4}\d{6})$/;
    var error = document.getElementById('usrError');
    if (!valCorreo.test(input.value)) {
      error.textContent = '* Employee ID or email are invalid.';
      input.style.borderColor = 'red'; // Establecer el borde rojo
      input.style.borderWidth = '2px'; // Establecer el ancho del borde
      return false;
    } else {
      error.textContent = '';
      input.style.borderColor = ''; // Establecer el borde rojo
      input.style.borderWidth = ''; // Establecer el ancho del borde
      return true;
    }
  }

/* ********************************************  VALIDACIÓN PARA LA ENTRADA DEL NOMBRE Y APELLIDOS ******************************************** */
function validarLetras(input) {
    // Elimina cualquier carácter que no sea una letra
    input.value = input.value.replace(/[^a-zA-ZáéíóúÁÉÍÓÚüÜñÑ\s]/g, '');
}

function validarMatricula(input) {
    var valMat = /^[A-Za-z]{4}\d{6}$/;
    var error = document.getElementById('matriculaError');
    if (!valMat.test(input.value)) {
      error.textContent = '* Invalid Employee ID.';
      return false;
    } else {
      error.textContent = '';
      return true;
    }
  }

  // Validación del correo en tiempo real
  function validarCorreo(input) {
    var valCorreo = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
    var error = document.getElementById('emailError');
    if (!valCorreo.test(input.value)) {
      error.textContent = '* Invalid Email.';
      input.style.borderColor = 'red'; // Establecer el borde rojo
      input.style.borderWidth = '2px'; // Establecer el ancho del borde
      return false;
    } else {
      error.textContent = '';
      input.style.borderColor = ''; // Establecer el borde rojo
      input.style.borderWidth = ''; // Establecer el ancho del borde
      return true;
    }
  }