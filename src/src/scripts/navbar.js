function $(id){
    return document.getElementById(id);
}
function navbar_button(element) {
    let selector_list = $('navbar-list_' + element);
    let selector_prefix = $('navbar-prefix_' + element);
    if(selector_list.style.display === 'none'){
        selector_prefix.innerHTML = '&#129171;';
        selector_list.style.display = 'block';
    }else{
        selector_prefix.innerHTML = '&#129170;';
        selector_list.style.display = 'none';
    }
}
function navbar_menu(){
    let selector = $('navbar');
    if(selector.style.display === ''){
        selector.style.display = 'block';
    }else{
        selector.style.display = '';
    }
}
window.addEventListener('DOMContentLoaded', function (){
    $('navbar-menu_0').addEventListener('click', navbar_menu, false)
    $('navbar-menu_1').addEventListener('click', navbar_menu, false)
    $('navbar-button_documents').addEventListener('click', function () {
        navbar_button('documents')
    }, false)
    $('navbar-button_about').addEventListener('click', function () {
        navbar_button('about')
    }, false)
}, false)
