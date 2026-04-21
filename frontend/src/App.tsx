import type { ReactNode } from 'react';
import { BrowserRouter, Routes, Route, Link, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  Server,
  Radar,
  BookOpen,
  PlayCircle,
  History,
  Shield,
  Activity,
  Code2,
  Package,
  Globe2,
  Bug,
  FileText,
  FileBarChart,
  Plug,
  Settings as SettingsIconLucide,
  Globe,
  Newspaper,
} from 'lucide-react';
import Dashboard from './pages/Dashboard';
import EasmDashboard from './pages/EasmDashboard';
import News from './pages/News';
import NewsArticleDetail from './pages/NewsArticle';
import Campaigns from './pages/Campaigns';
import Scanner from './pages/Scanner';
import Targets from './pages/Targets';
import ScenarioCatalog from './pages/ScenarioCatalog';
import Runs from './pages/Runs';
import EvidenceLogs from './pages/EvidenceLogs';
import Reports from './pages/Reports';
import Discovery from './pages/Discovery';
import IocThreat from './pages/IocThreat';
import WaapValidation from './pages/WaapValidation';
import DependencyRisk from './pages/DependencyRisk';
import MalwareFileRisk from './pages/MalwareFileRisk';
import CodeSecurity from './pages/CodeSecurity';
import TechIntel from './pages/TechIntel';
import Integrations from './pages/Integrations';
import Settings from './pages/Settings';
import Login from './pages/Login';
import Signup from './pages/Signup';
import ForgotPassword from './pages/ForgotPassword';
import ResetPassword from './pages/ResetPassword';
import VerifyEmail from './pages/VerifyEmail';
import Profile from './pages/Profile';
import { AuthProvider } from './auth/AuthContext';
import { ProtectedRoute, PublicRoute } from './auth/RouteGuards';
import UserMenu from './auth/UserMenu';
import { ThemeProvider } from './theme/ThemeContext';
import ThemeToggle from './theme/ThemeToggle';

const navItems: { name: string; path: string; icon: ReactNode }[] = [
  { name: 'Dashboard', path: '/', icon: <LayoutDashboard size={20} /> },
  { name: 'EASM Overview', path: '/easm', icon: <Globe size={20} /> },
  { name: 'Targets', path: '/targets', icon: <Server size={20} /> },
  { name: 'Discovery', path: '/discovery', icon: <Radar size={20} /> },
  { name: 'Scenario Catalog', path: '/scenario-catalog', icon: <BookOpen size={20} /> },
  { name: 'Campaigns', path: '/campaigns', icon: <PlayCircle size={20} /> },
  { name: 'Runs', path: '/runs', icon: <History size={20} /> },
  { name: 'WAAP Validation', path: '/waap-validation', icon: <Shield size={20} /> },
  { name: 'Tech Intelligence', path: '/tech-intel', icon: <Radar size={20} /> },
  { name: 'Application Assessment', path: '/scanner', icon: <Activity size={20} /> },
  { name: 'Code Security', path: '/code-security', icon: <Code2 size={20} /> },
  { name: 'CVE Intelligence', path: '/dependency-risk', icon: <Package size={20} /> },
  { name: 'IOC & Threat Context', path: '/ioc-threat', icon: <Globe2 size={20} /> },
  { name: 'News & Intelligence', path: '/news', icon: <Newspaper size={20} /> },
  { name: 'Malware & File Risk', path: '/malware-file-risk', icon: <Bug size={20} /> },
  { name: 'Evidence & Logs', path: '/evidence', icon: <FileText size={20} /> },
  { name: 'Reports', path: '/reports', icon: <FileBarChart size={20} /> },
  { name: 'Integrations', path: '/integrations', icon: <Plug size={20} /> },
  { name: 'Settings', path: '/settings', icon: <SettingsIconLucide size={20} /> },
];

const Sidebar = () => {
  const location = useLocation();

  return (
    <div className="w-64 bg-[#1a1d24] border-r border-[#2d333b] min-h-screen flex flex-col pt-6 shrink-0">
      <div className="px-6 mb-8 flex items-center space-x-3">
        <div className="w-8 h-8 rounded bg-gradient-to-br from-[#8e51df] to-[#4d1c8c] flex items-center justify-center">
          <Shield size={20} className="text-white" />
        </div>
        <div>
          <h1 className="text-lg font-bold text-white tracking-widest">UASF</h1>
          <span className="text-[10px] text-[#94a3b8] uppercase tracking-wider">
            Universal Attack Simulation
          </span>
        </div>
      </div>
      <nav className="flex-1 px-3 space-y-0.5 overflow-y-auto pb-6">
        {navItems.map((item) => {
          // Exact match for the dashboard ("/"), prefix match for everything
          // else so detail routes like /news/:id keep the parent nav lit up.
          const isActive =
            item.path === '/'
              ? location.pathname === '/'
              : location.pathname === item.path ||
                location.pathname.startsWith(`${item.path}/`);
          return (
            <Link
              key={item.path}
              to={item.path}
              className={`flex items-center space-x-3 px-3 py-2 rounded-md transition-all duration-200 ${
                isActive
                  ? 'bg-[#6a2bba]/20 text-[#8e51df] border border-[#6a2bba]/30 shadow-[inset_4px_0_0_0_#8e51df]'
                  : 'text-[#94a3b8] hover:text-white hover:bg-[#2d333b]/50'
              }`}
            >
              <div className={isActive ? 'text-[#8e51df]' : 'text-current'}>{item.icon}</div>
              <span className="font-medium text-sm leading-tight">{item.name}</span>
            </Link>
          );
        })}
      </nav>
      <div className="p-4 border-t border-[#2d333b] shrink-0">
        <div className="flex items-center space-x-3 text-sm text-[#94a3b8]">
          <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
          <span>
            Engine: <b className="text-white">Active</b>
          </span>
        </div>
      </div>
    </div>
  );
};

/**
 * Authenticated chrome: sidebar + top bar + content. Wrapped by ProtectedRoute
 * so the entire shell only renders for signed-in users.
 */
const Shell = ({ children }: { children: ReactNode }) => {
  return (
    <div className="flex min-h-screen bg-[#0f1115] text-[#e2e8f0]">
      <Sidebar />
      <main className="flex-1 overflow-y-auto w-full min-w-0">
        <div className="sticky top-0 z-20 backdrop-blur bg-[#0f1115]/80 border-b border-[#2d333b]">
          <div className="px-8 py-3 max-w-[1600px] mx-auto flex items-center justify-end gap-3">
            <ThemeToggle />
            <UserMenu />
          </div>
        </div>
        <div className="p-8 max-w-[1600px] mx-auto">{children}</div>
      </main>
    </div>
  );
};

/**
 * The top-level route table.
 *
 *   - /login, /signup, /forgot-password, /reset-password, /verify-email are
 *     wrapped with <PublicRoute> so an authenticated user is bounced back
 *     to the dashboard.
 *
 *   - Every other route is wrapped with <ProtectedRoute> so unauthenticated
 *     visitors are redirected to /login while preserving the intended path
 *     for post-login bounce-back.
 */
const App = () => {
  return (
    <ThemeProvider>
      <BrowserRouter>
        <AuthProvider>
          <Routes>
          {/* Public routes */}
          <Route
            path="/login"
            element={
              <PublicRoute>
                <Login />
              </PublicRoute>
            }
          />
          <Route
            path="/signup"
            element={
              <PublicRoute>
                <Signup />
              </PublicRoute>
            }
          />
          <Route
            path="/forgot-password"
            element={
              <PublicRoute>
                <ForgotPassword />
              </PublicRoute>
            }
          />
          <Route
            path="/reset-password"
            element={
              <PublicRoute>
                <ResetPassword />
              </PublicRoute>
            }
          />
          {/* Verify-email is reachable while logged in (e.g. for resend flows). */}
          <Route path="/verify-email" element={<VerifyEmail />} />

          {/* Protected routes */}
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <Shell>
                  <Dashboard />
                </Shell>
              </ProtectedRoute>
            }
          />
          <Route
            path="/easm"
            element={
              <ProtectedRoute>
                <Shell>
                  <EasmDashboard />
                </Shell>
              </ProtectedRoute>
            }
          />
          <Route
            path="/profile"
            element={
              <ProtectedRoute>
                <Shell>
                  <Profile />
                </Shell>
              </ProtectedRoute>
            }
          />
          <Route
            path="/targets"
            element={
              <ProtectedRoute>
                <Shell>
                  <Targets />
                </Shell>
              </ProtectedRoute>
            }
          />
          <Route
            path="/discovery"
            element={
              <ProtectedRoute>
                <Shell>
                  <Discovery />
                </Shell>
              </ProtectedRoute>
            }
          />
          <Route
            path="/scenario-catalog"
            element={
              <ProtectedRoute>
                <Shell>
                  <ScenarioCatalog />
                </Shell>
              </ProtectedRoute>
            }
          />
          <Route
            path="/campaigns"
            element={
              <ProtectedRoute>
                <Shell>
                  <Campaigns />
                </Shell>
              </ProtectedRoute>
            }
          />
          <Route
            path="/runs"
            element={
              <ProtectedRoute>
                <Shell>
                  <Runs />
                </Shell>
              </ProtectedRoute>
            }
          />
          <Route
            path="/waap-validation"
            element={
              <ProtectedRoute>
                <Shell>
                  <WaapValidation />
                </Shell>
              </ProtectedRoute>
            }
          />
          <Route
            path="/tech-intel"
            element={
              <ProtectedRoute>
                <Shell>
                  <TechIntel />
                </Shell>
              </ProtectedRoute>
            }
          />
          <Route
            path="/scanner"
            element={
              <ProtectedRoute>
                <Shell>
                  <Scanner />
                </Shell>
              </ProtectedRoute>
            }
          />
          <Route
            path="/code-security"
            element={
              <ProtectedRoute>
                <Shell>
                  <CodeSecurity />
                </Shell>
              </ProtectedRoute>
            }
          />
          <Route
            path="/dependency-risk"
            element={
              <ProtectedRoute>
                <Shell>
                  <DependencyRisk />
                </Shell>
              </ProtectedRoute>
            }
          />
          <Route
            path="/ioc-threat"
            element={
              <ProtectedRoute>
                <Shell>
                  <IocThreat />
                </Shell>
              </ProtectedRoute>
            }
          />
          <Route
            path="/news"
            element={
              <ProtectedRoute>
                <Shell>
                  <News />
                </Shell>
              </ProtectedRoute>
            }
          />
          <Route
            path="/news/:id"
            element={
              <ProtectedRoute>
                <Shell>
                  <NewsArticleDetail />
                </Shell>
              </ProtectedRoute>
            }
          />
          <Route
            path="/malware-file-risk"
            element={
              <ProtectedRoute>
                <Shell>
                  <MalwareFileRisk />
                </Shell>
              </ProtectedRoute>
            }
          />
          <Route
            path="/evidence"
            element={
              <ProtectedRoute>
                <Shell>
                  <EvidenceLogs />
                </Shell>
              </ProtectedRoute>
            }
          />
          <Route
            path="/reports"
            element={
              <ProtectedRoute>
                <Shell>
                  <Reports />
                </Shell>
              </ProtectedRoute>
            }
          />
          <Route
            path="/integrations"
            element={
              <ProtectedRoute>
                <Shell>
                  <Integrations />
                </Shell>
              </ProtectedRoute>
            }
          />
          <Route
            path="/settings"
            element={
              <ProtectedRoute roles={['admin']}>
                <Shell>
                  <Settings />
                </Shell>
              </ProtectedRoute>
            }
          />
          <Route
            path="*"
            element={
              <ProtectedRoute>
                <Shell>
                  <div className="flex flex-col items-center justify-center min-h-[50vh] text-[#94a3b8]">
                    <Shield size={48} className="mb-4 opacity-20" />
                    <h2 className="text-xl text-white">Not found</h2>
                    <p className="mt-2 text-sm">Use the sidebar to navigate.</p>
                  </div>
                </Shell>
              </ProtectedRoute>
            }
          />
          </Routes>
        </AuthProvider>
      </BrowserRouter>
    </ThemeProvider>
  );
};

export default App;
