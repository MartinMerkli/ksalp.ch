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