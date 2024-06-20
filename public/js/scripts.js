function hasheo() {
    var data = document.getElementById('data').value;
    var hashedData = CryptoJS.SHA256(data).toString();
    document.getElementById('hashed_data').innerText = hashedData;
    alert('Data hashed successfully.');
}

function actualizarFirmas(firmas) {
    var firmasCompletadasList = document.getElementById('firmasCompletadasList');
    var firmasPendientesList = document.getElementById('firmasPendientesList');
    firmasCompletadasList.innerHTML = ''; // Limpiar la lista de firmas completadas
    firmasPendientesList.innerHTML = ''; // Limpiar la lista de firmas pendientes

    if (firmas) {
        var firmasArray = firmas.split(','); // Suponiendo que las firmas estén separadas por comas
        firmasArray.forEach(function(firma) {
            var [matricula, status] = firma.trim().split(':');
            var li = document.createElement('li');
            li.textContent = matricula.trim();

            if (status.trim() === 'si') {
                firmasCompletadasList.appendChild(li);
            } else {
                firmasPendientesList.appendChild(li);
            }
        });
    } else {
        var li = document.createElement('li');
        li.textContent = 'No signatures required';
        firmasPendientesList.appendChild(li);
    }
}

function mostrarOcultarElemento() {
    var elemento = document.getElementById('botonVerf');
    elemento.style.display = 'block'; // Cambia 'block' por 'inline-block', 'flex', etc. según el caso
}

document.addEventListener('DOMContentLoaded', (event) => {
    // Obtén el elemento que contiene el valor de shouldExecute
    const executeContainer = document.getElementById('executeContainer');
    
    if (executeContainer) {
        // Obtén el valor de shouldExecute del atributo de datos
        const shouldExecute = executeContainer.getAttribute('data-should-execute');
        var firmas = document.getElementById(shouldExecute).getAttribute('data-firmas');
        actualizarFirmas(firmas);
        console.log('si');
    }
});

