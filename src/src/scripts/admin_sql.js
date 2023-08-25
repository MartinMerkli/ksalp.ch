function $_(element){
    return document.getElementById('admin-sql_' + element);
}
function admin_sql__run(event){
    if(event.which === 13 && !event.shiftKey){
        event.preventDefault();
        let command = $_('input').value;
        let xhttp = new XMLHttpRequest();
        xhttp.addEventListener('error', function (){
            alert('error');
        });
        xhttp.onreadystatechange = function () {
            if(xhttp.readyState === XMLHttpRequest.DONE){
                if(xhttp.status !== 200){
                    alert(`status code is ${xhttp.status}; response: ${xhttp.responseText}`);
                }else{
                    let response = JSON.parse(xhttp.responseText);
                    let output = '';
                    for(let i=0; i < response.length; i++){
                        output += '<tr>';
                        for(let j=0; j < response[i].length; j++){
                            output += '<td>';
                            output += String(response[i][j]);
                            output += '</td>';
                        }
                        output += '</tr>';
                    }
                    $_('table').innerHTML = output;
                    alert('loaded')
                }
            }
        }
        xhttp.open('POST', '/admin/sql/post', true);
        xhttp.setRequestHeader('Content-Type', 'text/plain');
        xhttp.send(command);
    }
}
window.addEventListener('DOMContentLoaded', function (){
    $_('input').addEventListener('keypress', admin_sql__run);
});
