/* ===================== PROJECT Z — main.js ===================== */

// --- Копирование IP в буфер обмена ---
const toast = document.getElementById('toast');
function showToast(msg){
  toast.textContent = msg;
  toast.classList.add('show');
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => toast.classList.remove('show'), 1600);
}
document.querySelectorAll('[data-copy]').forEach(btn => {
  btn.addEventListener('click', async () => {
    const ip = btn.getAttribute('data-copy');
    try {
      await navigator.clipboard.writeText(ip);
    } catch (e) {
      // запасной вариант для старых браузеров
      const ta = document.createElement('textarea');
      ta.value = ip; document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); } catch (_) {}
      ta.remove();
    }
    showToast('IP скопирован: ' + ip);
  });
});

// клик по самому IP тоже копирует
document.querySelectorAll('[data-ip]').forEach(el => {
  el.style.cursor = 'pointer';
  el.title = 'Нажми, чтобы скопировать';
  el.addEventListener('click', async () => {
    const ip = el.textContent.trim();
    try { await navigator.clipboard.writeText(ip); } catch (e) {}
    showToast('IP скопирован: ' + ip);
  });
});

// --- Показать / скрыть пароль ---
const eye = document.getElementById('eye');
const pw = document.getElementById('pw');
if (eye && pw) {
  eye.addEventListener('click', () => {
    pw.type = pw.type === 'password' ? 'text' : 'password';
    eye.style.opacity = pw.type === 'text' ? '1' : '.7';
  });
}

// --- Мобильное меню ---
const menuToggle = document.getElementById('menuToggle');
const topnav = document.querySelector('.topnav');
if (menuToggle && topnav) {
  menuToggle.addEventListener('click', () => topnav.classList.toggle('open'));
}

// --- Активная вкладка в боковом меню при скролле ---
const navLinks = Array.from(document.querySelectorAll('.snav'));
const sections = navLinks
  .map(a => document.querySelector(a.getAttribute('href')))
  .filter(Boolean);

function setActive() {
  const y = window.scrollY + 120;
  let current = sections[0];
  for (const s of sections) { if (s.offsetTop <= y) current = s; }
  navLinks.forEach(a => {
    const t = document.querySelector(a.getAttribute('href'));
    a.classList.toggle('active', t === current);
  });
}
if (sections.length) {
  window.addEventListener('scroll', setActive, { passive: true });
  setActive();
}

// закрыть мобильное меню по клику на пункт
navLinks.forEach(a => a.addEventListener('click', () => topnav && topnav.classList.remove('open')));
