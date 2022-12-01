function encrypt() {
    const encryptList = document.getElementById('encrypt-list');
    const password = document.getElementById('password');
    const encrypted = CryptoJS.AES.encrypt(encryptList.value, password.value)

    navigator.clipboard.writeText(encrypted);
    const liveToast = document.getElementById('liveToast');
    const toast = new bootstrap.Toast(liveToast);
    toast.show();

    if (window.isSecureContext
        && typeof navigator !== "undefined"
        && 'canShare' in navigator
        && 'share' in navigator
        && navigator.canShare(encrypted)) {
        navigator.share(encrypted);
    }
}

function decrypt() {
    const decryptList = document.getElementById('decrypt-list');
    const password = document.getElementById('password');
    const decrypted = CryptoJS.AES.decrypt(decryptList.value, password.value)

    const decryptResult = document.getElementById('decrypt-result');
    decryptResult.innerText = decrypted.toString(CryptoJS.enc.Utf8);
}