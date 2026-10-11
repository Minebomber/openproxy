import { useEffect, useState } from 'react';

export type Theme = 'system' | 'light' | 'dark';

export function useTheme() {
  const [theme, setTheme] = useState<Theme>(() => {
    try {
      const saved = localStorage.getItem('openproxy-theme');
      if (saved === 'light' || saved === 'dark') return saved;
    } catch {
      /* Use the system preference when storage is unavailable. */
    }
    return 'system';
  });
  useEffect(() => {
    const media = matchMedia('(prefers-color-scheme: dark)');
    const apply = () =>
      document.documentElement.classList.toggle(
        'dark',
        theme === 'dark' || (theme === 'system' && media.matches),
      );
    apply();
    try {
      localStorage.setItem('openproxy-theme', theme);
    } catch {
      /* The theme applies to this visit. */
    }
    media.addEventListener('change', apply);
    return () => media.removeEventListener('change', apply);
  }, [theme]);
  return { theme, setTheme };
}
