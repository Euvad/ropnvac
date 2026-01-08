function iso(d){return d.toISOString().slice(0,10)}

function getMonthsBetween(startISO, endISO){
  const start = new Date(startISO);
  const end = new Date(endISO);
  const months = [];
  let cur = new Date(start.getFullYear(), start.getMonth(), 1);
  const last = new Date(end.getFullYear(), end.getMonth(), 1);
  while(cur <= last){
    const year = cur.getFullYear();
    const month = cur.getMonth();
    const label = cur.toLocaleString('fr-FR', {month:'long', year:'numeric'});
    const monthStart = new Date(year, month, 1).toISOString().slice(0,10);
    const monthEnd = new Date(year, month+1, 0).toISOString().slice(0,10);
    months.push({year, month, label, monthStart, monthEnd});
    cur.setMonth(cur.getMonth()+1);
  }
  return months;
}

function renderMonth(root, monthObj, allowedStart, allowedEnd, selectedSet){
  const year = monthObj.year;
  const month = monthObj.month;
  const first = new Date(year, month, 1);
  const lastDay = new Date(year, month+1, 0).getDate();

  const grid = document.createElement('div');
  grid.className = 'calendar-grid-month';

  // Weekday headers (Mon..Sun) in French
  const weekdays = ['Lun','Mar','Mer','Jeu','Ven','Sam','Dim'];
  weekdays.forEach(w=>{
    const h = document.createElement('div');
    h.className = 'weekday-header';
    h.textContent = w;
    grid.appendChild(h);
  });

  // blanks before first day (convert Sun=0 => 6, Mon=1 => 0)
  const firstWeekday = (first.getDay()+6)%7;
  for(let i=0;i<firstWeekday;i++){
    const blank = document.createElement('div');
    blank.className = 'cal-cell empty';
    grid.appendChild(blank);
  }

  for(let d=1; d<=lastDay; d++){
    const dateObj = new Date(year, month, d);
    const ds = iso(dateObj);
    const cell = document.createElement('button');
    cell.type = 'button';
    cell.className = 'cal-cell';
    cell.dataset.date = ds;

    const dayNum = document.createElement('div');
    dayNum.className = 'day-num';
    dayNum.textContent = d;
    const dayName = document.createElement('div');
    dayName.className = 'day-name';
    dayName.textContent = weekdays[(dateObj.getDay()+6)%7];
    cell.appendChild(dayNum);
    cell.appendChild(dayName);

    // disabled if outside allowed range
    if(ds < allowedStart || ds > allowedEnd){
      cell.classList.add('disabled');
      cell.disabled = true;
    } else {
      if(selectedSet.has(ds)) {
        cell.classList.add('selected');
        const label = document.createElement('div');
        label.className = 'disponible-label';
        label.textContent = 'Disponible';
        cell.appendChild(label);
      }
      cell.addEventListener('click', ()=>{
        cell.classList.toggle('selected');
        const existingLabel = cell.querySelector('.disponible-label');
        if(cell.classList.contains('selected')){
          selectedSet.add(ds);
          // Trigger the pulse animation
          cell.classList.remove('pulse');
          void cell.offsetWidth; // trigger reflow
          cell.classList.add('pulse');
          if(!existingLabel){
            const label = document.createElement('div');
            label.className = 'disponible-label';
            label.textContent = 'Disponible';
            cell.appendChild(label);
          }
        } else {
          selectedSet.delete(ds);
          if(existingLabel) existingLabel.remove();
        }
      });
    }
    grid.appendChild(cell);
  }

  root.innerHTML = '';
  root.appendChild(grid);
}

document.addEventListener('DOMContentLoaded', ()=>{
  const root = document.getElementById('calendar-root');
  const monthSelect = document.getElementById('month-select');
  const prevBtn = document.getElementById('prev-month');
  const nextBtn = document.getElementById('next-month');
  const status = document.getElementById('status');
  const saveBtn = document.getElementById('save');

  const months = getMonthsBetween(START, END);
  months.forEach((m,i)=>{
    const opt = document.createElement('option');
    opt.value = i;
    opt.textContent = m.label;
    monthSelect.appendChild(opt);
  });

  // pick initial month as the month of START
  let current = 0;
  for(let i=0;i<months.length;i++){
    if(START >= months[i].monthStart && START <= months[i].monthEnd){ current = i; break; }
  }
  monthSelect.value = current;

  const selectedSet = new Set(SELECTED);

  function showCurrent(){
    const m = months[current];
    renderMonth(root, m, START, END, selectedSet);
    monthSelect.value = current;
  }

  prevBtn.addEventListener('click', ()=>{ if(current>0){ current--; showCurrent(); } });
  nextBtn.addEventListener('click', ()=>{ if(current<months.length-1){ current++; showCurrent(); } });
  monthSelect.addEventListener('change', ()=>{ current = parseInt(monthSelect.value,10); showCurrent(); });

  showCurrent();

  saveBtn.addEventListener('click', async ()=>{
    const dates = Array.from(selectedSet);
    status.textContent = 'Enregistrement...';
    try{
      function getCookie(name){ const v = document.cookie.match('(^|;)\\s*' + name + '\\s*=\\s*([^;]+)'); return v ? v.pop() : ''; }
      const csrfToken = getCookie('csrf_token');
      const res = await fetch('/save_availabilities', {
        method: 'POST',
        headers: {'Content-Type':'application/json', 'X-CSRFToken': csrfToken},
        body: JSON.stringify({dates})
      });
      const j = await res.json();
      if(j.ok){ status.textContent = 'Enregistr\u00e9'; }
      else { status.textContent = 'Erreur: '+(j.message||'inconnue'); }
    }catch(err){ status.textContent = 'Erreur r\u00e9seau'; }
    setTimeout(()=>{ status.textContent=''; }, 2500);
  });
});
