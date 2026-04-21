import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { LogOut, User as UserIcon, ShieldCheck, ChevronDown } from 'lucide-react';
import { useAuth } from './useAuth';

/**
 * Top-bar identity widget. Shows the user's initials, display name, role
 * badge, and a dropdown with profile + sign-out actions.
 */
export default function UserMenu() {
  const { user, logout } = useAuth();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onDocClick = (e: MouseEvent) => {
      if (!ref.current) return;
      if (!ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onDocClick);
    return () => document.removeEventListener('mousedown', onDocClick);
  }, []);

  if (!user) return null;
  const name = user.displayName?.trim() || user.email.split('@')[0];
  const initials = name
    .split(/\s+/)
    .map((w) => w.charAt(0))
    .slice(0, 2)
    .join('')
    .toUpperCase();

  const roleColor =
    user.role === 'admin'
      ? 'text-amber-300 border-amber-900/40 bg-amber-950/30'
      : user.role === 'operator'
        ? 'text-sky-300 border-sky-900/40 bg-sky-950/30'
        : 'text-[#94a3b8] border-[#2d333b] bg-[#15181e]';

  return (
    <div className="relative" ref={ref}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-3 px-3 py-1.5 rounded-lg border border-[#2d333b] hover:border-[#8e51df]/40 hover:bg-[#15181e]/80 transition"
      >
        <div className="w-8 h-8 rounded-full bg-gradient-to-br from-[#8e51df] to-[#4d1c8c] flex items-center justify-center text-white text-xs font-semibold">
          {initials || '·'}
        </div>
        <div className="hidden sm:flex flex-col items-start leading-tight">
          <span className="text-sm text-white">{name}</span>
          <span className={`text-[9px] px-1.5 py-0.5 rounded uppercase tracking-wider border ${roleColor} mt-0.5`}>
            {user.role}
          </span>
        </div>
        <ChevronDown size={14} className="text-[#94a3b8]" />
      </button>

      {open && (
        <div className="absolute right-0 mt-2 w-64 rounded-xl border border-[#2d333b] bg-[#15181e] shadow-xl shadow-black/40 z-30">
          <div className="px-4 py-3 border-b border-[#2d333b]">
            <div className="text-sm text-white truncate">{name}</div>
            <div className="text-xs text-[#94a3b8] truncate">{user.email}</div>
          </div>
          <div className="py-1">
            <Link
              to="/profile"
              onClick={() => setOpen(false)}
              className="flex items-center gap-2 px-4 py-2 text-sm text-[#cbd5e1] hover:bg-[#2d333b]/50"
            >
              <UserIcon size={14} className="text-[#8e51df]" /> Account &amp; security
            </Link>
            {user.role === 'admin' && (
              <div className="px-4 py-2 text-[10px] uppercase tracking-wider text-[#64748b] flex items-center gap-1.5">
                <ShieldCheck size={11} className="text-amber-300" /> Admin tools coming soon
              </div>
            )}
          </div>
          <div className="border-t border-[#2d333b] py-1">
            <button
              type="button"
              onClick={() => {
                setOpen(false);
                void logout();
              }}
              className="flex items-center gap-2 px-4 py-2 text-sm text-red-300 hover:bg-red-950/30 w-full text-left"
            >
              <LogOut size={14} /> Sign out
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
