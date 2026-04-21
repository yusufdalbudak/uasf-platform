import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';

/**
 * UASF Theme Context
 *
 * Implements a non-invasive light / dark / system theme system on top
 * of an existing app whose component tree was authored against a
 * fixed dark palette (lots of hard-coded `bg-[#0f1115]`, `text-white`,
 * etc. classes — too many to migrate by hand without regressions).
 *
 * Strategy:
 *
 *   - This provider is the *only* state holder.  It writes the user's
 *     preference (`light` | `dark` | `system`) to `localStorage` under
 *     the key `uasf:theme`.  It listens to the OS-level `prefers-
 *     color-scheme` media query so a `system` user transitions live
 *     when they flip their OS appearance setting.
 *
 *   - The *resolved* theme (`light` or `dark`) is reflected on the
 *     `<html>` element as both a class (`light` / `dark`) and a
 *     `data-theme` attribute, so CSS overrides can target either.
 *
 *   - The companion `themeOverrides.css` provides the actual visual
 *     remap for `data-theme="light"`.  No component edits are needed
 *     for the theme to take effect — flipping the attribute on
 *     `<html>` is enough.
 *
 *   - `ThemeProvider` MUST be installed above the app shell so the
 *     attribute is set before any styled subtree mounts; otherwise
 *     there is a brief dark-mode flash on first paint.  We also
 *     hydrate from localStorage in a synchronous useState init so the
 *     very first React render already has the right value.
 */

type ThemeChoice = 'light' | 'dark' | 'system';
type ResolvedTheme = 'light' | 'dark';

const STORAGE_KEY = 'uasf:theme';

interface ThemeContextValue {
  /** What the user chose (or `system` by default). */
  choice: ThemeChoice;
  /** What is actually applied right now (system → resolved). */
  resolved: ResolvedTheme;
  /** Persist a new preference.  System triggers a live OS query. */
  setChoice: (next: ThemeChoice) => void;
  /** Convenience: flip between light and dark, ignoring `system`. */
  toggle: () => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

function readStoredChoice(): ThemeChoice {
  if (typeof window === 'undefined') return 'dark';
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (raw === 'light' || raw === 'dark' || raw === 'system') return raw;
  } catch {
    /* localStorage may be disabled in some embed contexts. */
  }
  return 'dark';
}

function detectSystemTheme(): ResolvedTheme {
  if (typeof window === 'undefined' || !window.matchMedia) return 'dark';
  return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

function applyToDocument(resolved: ResolvedTheme) {
  if (typeof document === 'undefined') return;
  const root = document.documentElement;
  root.dataset.theme = resolved;
  root.classList.remove('theme-light', 'theme-dark');
  root.classList.add(`theme-${resolved}`);
  // We also set `color-scheme` so native form controls (scrollbars,
  // selects, date pickers) match the chosen palette automatically.
  root.style.colorScheme = resolved;
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [choice, setChoiceState] = useState<ThemeChoice>(() => readStoredChoice());
  const [systemTheme, setSystemTheme] = useState<ResolvedTheme>(() => detectSystemTheme());

  // Track OS preference for the `system` setting.
  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return;
    const mq = window.matchMedia('(prefers-color-scheme: light)');
    const handler = (e: MediaQueryListEvent) => setSystemTheme(e.matches ? 'light' : 'dark');
    if (mq.addEventListener) mq.addEventListener('change', handler);
    else mq.addListener(handler);
    return () => {
      if (mq.removeEventListener) mq.removeEventListener('change', handler);
      else mq.removeListener(handler);
    };
  }, []);

  const resolved: ResolvedTheme = choice === 'system' ? systemTheme : choice;

  // Apply on mount + every time the resolved theme changes.
  useEffect(() => {
    applyToDocument(resolved);
  }, [resolved]);

  const setChoice = useCallback((next: ThemeChoice) => {
    setChoiceState(next);
    try {
      window.localStorage.setItem(STORAGE_KEY, next);
    } catch {
      /* ignore storage failures */
    }
  }, []);

  const toggle = useCallback(() => {
    setChoice(resolved === 'dark' ? 'light' : 'dark');
  }, [resolved, setChoice]);

  const value = useMemo<ThemeContextValue>(
    () => ({ choice, resolved, setChoice, toggle }),
    [choice, resolved, setChoice, toggle],
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) {
    throw new Error('useTheme must be used inside <ThemeProvider>.');
  }
  return ctx;
}

/**
 * Pre-React inline script body that flips the `<html>` attribute
 * before the first React render so we never flash the wrong theme.
 * Embed in `index.html` to opt into the no-flash boot path.
 */
export const NO_FLASH_INLINE_SCRIPT = `
(function(){try{
  var v = localStorage.getItem('${STORAGE_KEY}');
  var resolved = v === 'light' ? 'light'
    : v === 'dark' ? 'dark'
    : (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
  document.documentElement.setAttribute('data-theme', resolved);
  document.documentElement.classList.add('theme-' + resolved);
  document.documentElement.style.colorScheme = resolved;
}catch(e){}})();
`;
