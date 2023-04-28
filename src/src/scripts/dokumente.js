let dokumente__documents;

function dokumente__sort(key, desc){
    dokumente__documents.sort(function (a, b){
        return a[key].localeCompare(b[key]);
    });
    if(desc){
        dokumente__documents = dokumente__documents.reverse();
    }
    dokumente__reload();
}
function dokumente__reload(){
    function $_(id){
        return document.getElementById('dokumente_input_' + id);
    }
    let inputs = ['title', 'class', 'grade', 'subject', 'language', 'extension', 'owner', 'time1-start', 'time1-end', 'time2-start', 'time2-end']
    let included = [];
    let copy = [];
    let keys = [];
    if(dokumente__documents.length > 0){
        keys = Object.keys(dokumente__documents[0]);
    }
    for(let i=0; i < dokumente__documents.length; i++){
        let tmp = {};
        for(let j=0; j < keys.length; j++){
            tmp[keys[j]] = dokumente__documents[i][keys[j]].toLowerCase();
        }
        copy.push(tmp);
    }
    for(let i=0; i < inputs.length; i++){
        let value = $_(inputs[i]).value.toLowerCase();
        if(value !== ''){
            for(let j=0; j < copy.length; j++){
                if(included.includes(j)){/* pass */
                }else if(inputs[i] === 'time1-start'){
                    if(copy[j]['created'].localeCompare(value) > 0){
                        included.push(j);
                    }
                }else if(inputs[i] === 'time1-end'){
                    if(copy[j]['created'].localeCompare(value) < 0){
                        included.push(j);
                    }
                }else if(inputs[i] === 'time2-start'){
                    if(copy[j]['edited'].localeCompare(value) > 0){
                        included.push(j);
                    }
                }else if(inputs[i] === 'time2-end'){
                    if(copy[j]['edited'].localeCompare(value) < 0){
                        included.push(j);
                    }
                }else{
                    if(copy[j][inputs[i]].includes(value)){
                        included.push(j);
                    }
                }
            }
        }
    }
    let content = '';
    for(let i=0; i < dokumente__documents.length; i++){
        if(included.includes(i)){
            content += `<div onclick="window.location.href = '/dokumente/vorschau/${dokumente__documents[i]['id']}'">
<h3><b>${dokumente__documents[i]['subject']}</b> ${dokumente__documents[i]['title']}</h3>
<p>[${dokumente__documents[i]['extension'].toUpperCase()}] Zuletzt bearbeitet am 
${dokumente__documents[i]['edited'].split('_')[0]}, erstellt am ${dokumente__documents[i]['created'].split('_')[0]} 
von <i>${dokumente__documents[i]['owner']}</i></p></div>`;
        }
    }
    $('dokumente_box').innerHTML = content;
}
const dokumente__dataset = document.currentScript.dataset;
window.addEventListener('DOMContentLoaded', async function (){
    let dokumente__response;
    if (dokumente__dataset['class'] !== ''){
        dokumente__response = await fetch('/dokumente/documents.json?class=' + dokumente__dataset['class']);
    } else if (dokumente__dataset['grade'] !== ''){
        dokumente__response = await fetch('/dokumente/documents.json?grade=' + dokumente__dataset['grade']);
    } else {
        dokumente__response = await fetch('/dokumente/documents.json');
    }
    let dokumente__documents = await dokumente__response.json();
    function $_(id){
        return document.getElementById(id);
    }
    dokumente__sort('edited', true);
    const dokumente__id_list = ['title', 'class', 'grade', 'subject', 'language', 'extension', 'owner',
        'time1-start', 'time1-end', 'time2-start', 'time2-end'];
    for (let i=0; i < dokumente__id_list.length; i++) {
        $_('dokumente_input_' + dokumente__id_list[i]).addEventListener('keyup', dokumente__reload, false);
    }
    $_('dokumente_sort_edited-t').addEventListener('click', function () {
        dokumente__sort('edited', true);
    }, false);
    $_('dokumente_sort_edited-f').addEventListener('click', function () {
        dokumente__sort('edited', false);
    }, false);
    $_('dokumente_sort_created-t').addEventListener('click', function () {
        dokumente__sort('created', true);
    }, false);
    $_('dokumente_sort_created-f').addEventListener('click', function () {
        dokumente__sort('created', false);
    }, false);
}, false);
