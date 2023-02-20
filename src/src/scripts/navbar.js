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
