function lernsets__sort(key, desc){
    lernsets__sets.sort(function (a, b){
        return a[key].localeCompare(b[key]);
    });
    if(desc){
        lernsets__sets = lernsets__sets.reverse();
    }
    lernsets__reload();
}
function lernsets__reload(){
    function $_(id){
        return document.getElementById('lernsets_input_' + id);
    }
    let inputs = ['title', 'class', 'grade', 'subject', 'language', 'owner', 'time1-start', 'time1-end', 'time2-start', 'time2-end']
    let ignored = [];
    let copy = [];
    let keys = [];
    if(lernsets__sets.length > 0){
        keys = Object.keys(lernsets__sets[0]);
    }
    for(let i=0; i < lernsets__sets.length; i++){
        let tmp = {};
        for(let j=0; j < keys.length; j++){
            tmp[keys[j]] = lernsets__sets[i][keys[j]].toLowerCase();
        }
        copy.push(tmp);
    }
    for(let i=0; i < inputs.length; i++){
        if(!((lernsets__dataset['class'] !== '') && (inputs[i] === 'class')) && !((lernsets__dataset['grade'] !== '') && (inputs[i] === 'grade'))){
            let value = $_(inputs[i]).value.toLowerCase();
            if(value !== ''){
                for(let j=0; j < copy.length; j++){
                    if(ignored.includes(j)){/* pass */
                    }else if(inputs[i] === 'time1-start'){
                        if(copy[j]['created'].localeCompare(value) < 0){
                            ignored.push(j);
                        }
                    }else if(inputs[i] === 'time1-end'){
                        if(copy[j]['created'].localeCompare(value) > 0){
                            ignored.push(j);
                        }
                    }else if(inputs[i] === 'time2-start'){
                        if(copy[j]['edited'].localeCompare(value) < 0){
                            ignored.push(j);
                        }
                    }else if(inputs[i] === 'time2-end'){
                        if(copy[j]['edited'].localeCompare(value) > 0){
                            ignored.push(j);
                        }
                    }else{
                        if(!(copy[j][inputs[i]].includes(value))){
                            ignored.push(j);
                        }
                    }
                }
            }
        }
    }
    let content = '<input type="submit" name="submit" value="Lernmodus starten" class="input-button center"><div class="lernsets_box">';
    for(let i=0; i < lernsets__sets.length; i++){
        if(!(ignored.includes(i))){
            content += `<label id="${lernsets__sets[i]['id']}">
<h3><b>${lernsets__sets[i]['subject']}</b> ${lernsets__sets[i]['title']}</h3>
<span><a href="/lernsets/vorschau/${lernsets__sets[i]['id']}">Vorschau</a></span>
<p> Zuletzt bearbeitet am 
${lernsets__sets[i]['edited'].split('_')[0]}, erstellt am ${lernsets__sets[i]['created'].split('_')[0]} 
von <i>${lernsets__sets[i]['owner']}</i></p>
<input type="checkbox" name="${lernsets__sets[i]['id']}" value="${lernsets__sets[i]['id']}"></label>`;
        }
    }
    content += `</div><input type="submit" name="submit" value="Lernmodus starten" class="input-button center">`;
    $('lernsets_box').innerHTML = content;
}
const lernsets__dataset = document.currentScript.dataset;
let lernsets__sets = {};
window.addEventListener('DOMContentLoaded', async function (){
    let lernsets__response;
    if (lernsets__dataset['class'] !== ''){
        lernsets__response = await fetch('/lernsets/sets.json?as_list=true&class=' + lernsets__dataset['class']);
    } else if (lernsets__dataset['grade'] !== ''){
        lernsets__response = await fetch('/lernsets/sets.json?as_list=true&grade=' + lernsets__dataset['grade']);
    } else {
        lernsets__response = await fetch('/lernsets/sets.json?as_list=true');
    }
    lernsets__sets = await lernsets__response.json();
    function $_(id){
        return document.getElementById(id);
    }
    lernsets__sort('edited', true);
    const lernsets__id_list = ['title', 'class', 'grade', 'subject', 'language', 'owner',
        'time1-start', 'time1-end', 'time2-start', 'time2-end'];
    for (let i=0; i < lernsets__id_list.length; i++) {
        $_('lernsets_input_' + lernsets__id_list[i]).addEventListener('keyup', lernsets__reload, false);
    }
    $_('lernsets_sort_edited-t').addEventListener('click', function () {
        lernsets__sort('edited', true);
    }, false);
    $_('lernsets_sort_edited-f').addEventListener('click', function () {
        lernsets__sort('edited', false);
    }, false);
    $_('lernsets_sort_created-t').addEventListener('click', function () {
        lernsets__sort('created', true);
    }, false);
    $_('lernsets_sort_created-f').addEventListener('click', function () {
        lernsets__sort('created', false);
    }, false);
    navbar_button('learning');
}, false);
