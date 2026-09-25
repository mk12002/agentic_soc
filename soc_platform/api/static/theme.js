// Applied before first paint so the page never flashes the wrong theme. Light unless the user chose dark.
(function () {
  var t = 'light';
  try { t = localStorage.getItem('soc_theme') === 'dark' ? 'dark' : 'light'; } catch (e) { /* storage blocked */ }
  document.documentElement.setAttribute('data-theme', t);
})();
