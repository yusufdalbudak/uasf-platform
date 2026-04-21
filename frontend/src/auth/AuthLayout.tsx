import type { ReactNode } from 'react';
import { Shield } from 'lucide-react';

/**
 * Shared chrome for unauthenticated pages (login, signup, forgot password, ...).
 * Centralises the brand panel + glass card aesthetic so each page only ships
 * its form contents.
 */
export default function AuthLayout({
  title,
  subtitle,
  children,
  footer,
}: {
  title: string;
  subtitle?: string;
  children: ReactNode;
  footer?: ReactNode;
}) {
  return (
    <div className="min-h-screen flex bg-[#0f1115] text-[#e2e8f0]">
      {/* Brand pane */}
      <div className="hidden md:flex w-[42%] flex-col p-12 bg-gradient-to-br from-[#1a1d24] via-[#161922] to-[#0f1115] border-r border-[#2d333b]">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-[#8e51df] to-[#4d1c8c] flex items-center justify-center shadow-lg shadow-[#4d1c8c]/30">
            <Shield size={22} className="text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white tracking-widest">UASF</h1>
            <span className="text-[10px] text-[#94a3b8] uppercase tracking-wider">
              Universal Attack Simulation Framework
            </span>
          </div>
        </div>
        <div className="mt-auto">
          <h2 className="text-2xl text-white font-semibold leading-tight">
            Vendor-agnostic security validation, end to end.
          </h2>
          <p className="mt-3 text-sm text-[#94a3b8] leading-relaxed max-w-md">
            UASF orchestrates WAAP validation, application assessment, dependency intelligence,
            IOC correlation, malware triage, and operator-grade reporting from one console.
          </p>
          <div className="mt-8 flex items-center space-x-2 text-xs text-[#94a3b8]">
            <div className="w-2 h-2 rounded-full bg-green-500" />
            <span>Authenticated · Audit-logged · Session-isolated</span>
          </div>
        </div>
      </div>

      {/* Form pane */}
      <div className="flex-1 flex items-center justify-center p-6 md:p-12">
        <div className="w-full max-w-md">
          <div className="md:hidden flex items-center space-x-3 mb-8">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-[#8e51df] to-[#4d1c8c] flex items-center justify-center">
              <Shield size={18} className="text-white" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-white tracking-widest">UASF</h1>
            </div>
          </div>
          <h2 className="text-2xl text-white font-semibold">{title}</h2>
          {subtitle && <p className="mt-1.5 text-sm text-[#94a3b8]">{subtitle}</p>}
          <div className="mt-6">{children}</div>
          {footer && <div className="mt-6 text-sm text-[#94a3b8]">{footer}</div>}
        </div>
      </div>
    </div>
  );
}
