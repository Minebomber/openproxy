let theme;
try {
  theme = localStorage.getItem('openproxy-theme');
} catch {}
document.documentElement.classList.toggle(
  'dark',
  theme === 'dark' || (theme !== 'light' && matchMedia('(prefers-color-scheme: dark)').matches),
);
