function validacion_regs(){
  var usuario = document.getElementById('matricula').value; //correo o matricula del tipo: (10 caracteres) 4letras6numeros
  var contrasena = document.getElementById('contras').value;
  var correo = document.getElementById('email').value;

  /* +++++++++++++++++++++++++++++++  VALIDACIÓN PARA EL CORREO ELECTRÓNICO O MATRICULA +++++++++++++++++++++++++++++++ */
  var valMat = /^[A-Za-z]{4}\d{6}$/;
  var valCorreo = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
  if(!valMat.test(usuario)){
    return false;
  }
  if(!valCorreo.test(correo)){
    return false;
  }
  if (contrasena.length < 8) {
      return false;
  }

  // Validar al menos un número
  if (!/\d/.test(contrasena)) {
    return false;
  }

  // Validar al menos un carácter especial
  if (!/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(contrasena)) {
    return false;
  }

  return true; //todas las validaciones correctas
}

 // Validación del correo o matricula en tiempo real
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


// Validación del matricula en tiempo real
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

//validación de contraseña en tiempo real
function validarContra(input) {
  var contrasena = input.value;
  var mensajeValidacion = document.getElementById('psswordError');
  var esValida = true;

  // Resetear el mensaje de error antes de realizar las validaciones
  mensajeValidacion.textContent = '';

  // Validar longitud mínima
  if (contrasena.length < 8) {
      mensajeValidacion.textContent = '* Password must be at least 8 characters long.';
      esValida = false;
  }

  // Validar al menos un número
  if (!/\d/.test(contrasena)) {
      mensajeValidacion.textContent = '* Password must contain at least one number.';
      esValida = false;
  }

  // Validar al menos un carácter especial
  if (!/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(contrasena)) {
      mensajeValidacion.textContent = '* Password must contain at least one special character.';
      esValida = false;
  }

  // Si la contraseña es válida, limpiar el mensaje de error
  if (esValida) {
      mensajeValidacion.textContent = '';
  }

  return esValida;
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