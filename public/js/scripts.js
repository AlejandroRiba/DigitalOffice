function hasheo() {
    var data = document.getElementById('data').value;
    var hashedData = CryptoJS.SHA256(data).toString();
    document.getElementById('hashed_data').innerText = hashedData;
    alert('Data hashed successfully.');
}



