function konto_einstellungen__password_check(){
    let result = zxcvbn($('konto-einstellungen_password_password-new').value);
    const ratings = ['sehr schlecht', 'schlecht', 'schwach', 'akzeptabel', 'stark'];
    $('konto-einstellungen_password_password-info').innerHTML = '[' + ratings[result.score] + ']';
}
function konto_einstellungen__password_match(){
    const password = $('konto-einstellungen_password_password-new');
    const password_repeat = $('konto-einstellungen_password_password-new-repeat');
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
    $_('konto-einstellungen_password-new').addEventListener('keyup', function () {
        konto_einstellungen__password_check();
        konto_einstellungen__password_match();
    }, false);
    $_('konto-einstellungen_password-new-repeat').addEventListener('keyup', konto_einstellungen__password_match, false);
}, false);
