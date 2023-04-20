function konto_registrieren__password_check(){
    let result = zxcvbn($('konto-registrieren_password').value);
    const ratings = ['sehr schlecht', 'schlecht', 'schwach', 'akzeptabel', 'stark'];
    $('konto-registrieren_password-info').innerHTML = '[' + ratings[result.score] + ']';
}
function konto_registrieren__password_match(){
    const password = $('konto-registrieren_password');
    const password_repeat = $('konto-registrieren_password-repeat');
    if(password.value === password_repeat.value){
        password_repeat.setCustomValidity('');
    }else{
        password_repeat.setCustomValidity('Passwörter sind unterschiedlich.');
    }
}
window.addEventListener('DOMContentLoaded', function () {
    function $_(id) {
        return document.getElementById(id);
    }
    $_('konto-registrieren_password').addEventListener('keyup', function () {
        konto_registrieren__password_check();
        konto_registrieren__password_match();
    }, false);
    $_('konto-registrieren_password-repeat').addEventListener('keyup', konto_registrieren__password_match, false);
}, false);
