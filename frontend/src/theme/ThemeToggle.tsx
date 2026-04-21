import { Moon, Sun } from 'lucide-react';
import { useTheme } from './ThemeContext';

/**
 * Compact toolbar control rendered in the top-right of the app shell
 * next to the user menu.  One click flips between light and dark
 * (skipping `system`); the visible icon mirrors the *current* resolved
 * theme so the operator always knows which mode they're in.
 *
 * For the more granular Light / Dark / System tri-state choice, see
 * the Appearance section in the Settings page.
 */
export default function ThemeToggle() {
  const { resolved, toggle } = useTheme();
  const isDark = resolved === 'dark';
  return (
    <button
      type="button"
      onClick={toggle}
      title={isDark ? 'Switch to light theme' : 'Switch to dark theme'}
      aria-label={isDark ? 'Switch to light theme' : 'Switch to dark theme'}
      className="inline-flex items-center justify-center w-9 h-9 rounded-lg border border-[#2d333b] bg-[#15181e] text-[#cbd5e1] hover:border-[#8e51df]/40 hover:bg-[#1e232b] transition"
    >
      {isDark ? <Sun size={16} /> : <Moon size={16} />}
    </button>
  );
}
