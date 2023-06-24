let lernsets_learn__sets = {};
let lernsets_learn__stats = {};
let lernsets_learn__exercises = {};
let lernsets_learn__current = '';
let lernsets_learn__windows = ['connection-error', 'other-error', 'loading', 'exercise', 'result'];
let lernsets_learn__login = false;
let lernsets_learn__selected = [];
function $_(element){
    return document.getElementById('lernsets-learn_' + element);
}
function lernsets_learn__switch_window(new_front){
    for(let i in lernsets_learn__windows){
        $_('div_' + lernsets_learn__windows[i]).style.display = 'none';
    }
    $_('div_' + new_front).style.display = '';
}
function lernsets_learn__update_stats(){
    let correct = 0;
    let wrong = 0;
    let answered = 0;
    for(let i in lernsets_learn__stats){
        if(lernsets_learn__exercises.hasOwnProperty(i)){
            correct += lernsets_learn__stats[i]['correct'];
            wrong += lernsets_learn__stats[i]['wrong'];
            answered += 1;
        }
    }
    let total = Object.keys(lernsets_learn__exercises).length;
    let progress = '--%';
    if(total !== 0){
        progress = Math.round(((correct + wrong) / total) * 100).toString() + '%';
    }
    let grade = '~ -';
    if((correct + wrong) !== 0){
        grade = '~' + (Math.round((((correct / (correct + wrong)) * 5) + 1) * 10) / 10).toString();
    }
    let stats = `Fortschritt: ${progress} | Note: ${grade} | Total: ${answered} von ${total}`;
    $_('exercise-stats').innerText = stats;
    $_('result-stats').innerText = stats;
    let name = '';
    for(let i in lernsets_learn__sets){
        if(lernsets_learn__selected.includes(i)){
            name += `[${lernsets_learn__sets[i]['subject'].toUpperCase()}] ${lernsets_learn__sets[i]['title']}, `;
        }
    }
    if(name.length >= 2){
        name = name.slice(0, -2);
    }
    $_('exercise-name').innerText = name;
    $_('result-name').innerText = name;
    let id = `Aufgabe #${lernsets_learn__current.split('.')[1]} vom Lernset 
    '${lernsets_learn__sets[lernsets_learn__exercises[lernsets_learn__current]['set_id']]['title']}' 
    (#${lernsets_learn__exercises[lernsets_learn__current]['set_id']})`;
    $_('exercise-id').innerText = id;
    $_('result-id').innerText = id;
}
function lernsets_learn__connection_error(e=''){
    console.error(`an error occurred while trying to connect to the server: \n    ${e}`);
    $_('connection-error').style.display = '';
}
function lernsets_learn__save_answer(exercise_id, answer, correct){
    if(lernsets_learn__stats.hasOwnProperty(exercise_id)){
        if(correct){
            if(lernsets_learn__stats[exercise_id].hasOwnProperty('correct')){
                lernsets_learn__stats[exercise_id]['correct'] += 1;
            }else{
                lernsets_learn__stats[exercise_id]['correct'] = 1;
                lernsets_learn__stats[exercise_id]['wrong'] = 0;
            }
        }else{
            if(lernsets_learn__stats[exercise_id].hasOwnProperty('wrong')){
                lernsets_learn__stats[exercise_id]['wrong'] += 1;
            }else{
                lernsets_learn__stats[exercise_id]['wrong'] = 1;
                lernsets_learn__stats[exercise_id]['correct'] = 0;
            }
        }
    }else{
        if(correct){
            lernsets_learn__stats[exercise_id] = {'correct': 1, 'wrong': 0};
        }else{
            lernsets_learn__stats[exercise_id] = {'correct': 0, 'wrong': 1};
        }
    }
    if(lernsets_learn__login){
        lernsets_learn__send_answer(exercise_id, answer, correct);
    }
}
function lernsets_learn__send_answer(exercise_id, answer, correct){
    let xhttp = new XMLHttpRequest();
    xhttp.addEventListener('error', lernsets_learn__connection_error);
    xhttp.onreadystatechange = function () {
        if(xhttp.readyState === XMLHttpRequest.DONE){
            if(xhttp.status !== 200){
                lernsets_learn__connection_error(`status code is ${xhttp.status}`);
            }
        }
    }
    xhttp.open('POST', '/lernsets/statistics', true);
    xhttp.setRequestHeader('Content-Type', 'application/json');
    xhttp.send(JSON.stringify({'exercise_id': exercise_id, 'answer': answer, 'correct': correct}));
}
function lernsets_learn__next_exercise(){
    lernsets_learn__switch_window('loading');
    let chances = {};
    for(let i in lernsets_learn__exercises){
        if(lernsets_learn__stats.hasOwnProperty(i)){
            if(lernsets_learn__stats[i]['wrong'] > lernsets_learn__stats[i]['correct']){
                chances[i] = 1000 * lernsets_learn__exercises[i]['frequency'];
            }else{
                chances[i] = Math.max(0.05, 3 * lernsets_learn__stats[i]['wrong'] - 2 * lernsets_learn__stats[i]['correct'] + 1) * lernsets_learn__exercises[i]['frequency'];
            }
        }else{
            chances[i] = 4 * lernsets_learn__exercises[i]['frequency'] + 1;
        }
    }
    let total = 0.0;
    for(let i in chances){
        total += chances[i];
    }
    if(total < 0.001){
        lernsets_learn__switch_window('other-error');
        throw new Error('total is smaller than 0.001');
    }
    let choice = total * Math.random();
    let next_exercise = '';
    let total2 = 0.0;
    for(let i in chances){
        if((next_exercise === '') && ((chances[i] + total2) >= choice)){
            next_exercise = i;
        }
        total2 += chances[i];
    }
    lernsets_learn__current = next_exercise;
    $_('input').value = '';
    $_('question').innerText = lernsets_learn__exercises[lernsets_learn__current]['question'];
    lernsets_learn__update_stats();
    lernsets_learn__switch_window('exercise');
    $_('input').focus();
}
function lernsets_learn__check_answer(answer){
    return lernsets_learn__exercises[lernsets_learn__current]['answers'].split('$').includes(answer);
}
function lernsets_learn__submit(){
    lernsets_learn__switch_window('loading')
    let input = $_('input').value;
    if(lernsets_learn__check_answer(input)){
        lernsets_learn__save_answer(lernsets_learn__current, input, true);
        lernsets_learn__next_exercise();
        return null;
    }
    $_('result-question').innerText = lernsets_learn__exercises[lernsets_learn__current]['question'];
    $_('solution').innerText = lernsets_learn__exercises[lernsets_learn__current]['answer'];
    $_('answer').innerText = input;
    lernsets_learn__update_stats();
    lernsets_learn__switch_window('result');
    $_('correct').focus();
}
function lernsets_learn__enter(event){
    if(event.which === 13 && !event.shiftKey){
        lernsets_learn__submit();
        event.preventDefault();
    }
}
const lernsets_learn__dataset = document.currentScript.dataset;
lernsets_learn__selected = lernsets_learn__dataset['sets'].split('$');
window.addEventListener('DOMContentLoaded', async function (){
    lernsets_learn__switch_window('loading');
    $_('input').addEventListener('keypress', lernsets_learn__enter);
    $_('correct').addEventListener('click', function (){
        let answer = $_('input').value;
        lernsets_learn__save_answer(lernsets_learn__current, answer, true);
        lernsets_learn__next_exercise();
    });
     $_('wrong').addEventListener('click', function (){
        let answer = $_('input').value;
        lernsets_learn__save_answer(lernsets_learn__current, answer, false);
        lernsets_learn__next_exercise();
    });
    if(lernsets_learn__dataset['login'] !== ''){
        lernsets_learn__login = true;
    }
    let lernsets_learn__sets_response = await fetch('/lernsets/sets.json?sets=' + lernsets_learn__dataset['sets']);
    lernsets_learn__sets = await lernsets_learn__sets_response.json();
    let lernsets_learn__exercises_response = await fetch('lernsets/exercises.json?sets=' + lernsets_learn__dataset['sets']);
    lernsets_learn__exercises = await lernsets_learn__exercises_response.json();
    let lernsets_learn__stats_response = await fetch('lernsets/stats.json?sets=' + lernsets_learn__dataset['sets']);
    lernsets_learn__stats = await lernsets_learn__stats_response.json();
    lernsets_learn__next_exercise();
}, false);
