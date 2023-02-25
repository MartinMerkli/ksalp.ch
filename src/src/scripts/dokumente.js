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
