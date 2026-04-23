import React from 'react';
import {
  BarChart3,
  Upload,
  AlertCircle,
  FileText,
  History,
  Settings,
  Home,
} from 'lucide-react';

interface SidebarProps {
  isOpen: boolean;
  currentPage: string;
  setCurrentPage: (page: string) => void;
}

interface NavItem {
  id: string;
  label: string;
  icon: React.ReactNode;
  badge?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({ isOpen, currentPage, setCurrentPage }) => {
  const navItems: NavItem[] = [
    { id: 'dashboard', label: 'Dashboard', icon: <Home size={20} /> },
    { id: 'upload', label: 'Analyze File', icon: <Upload size={20} /> },
    { id: 'alerts', label: 'Alerts', icon: <AlertCircle size={20} />, badge: 3 },
    { id: 'reports', label: 'Reports', icon: <FileText size={20} /> },
    { id: 'history', label: 'History', icon: <History size={20} /> },
  ];

  return (
    <>
      {/* Overlay for mobile */}
      {isOpen && (
        <div
          className="fixed inset-0 bg-black bg-opacity-50 md:hidden z-40"
          onClick={() => setCurrentPage(currentPage)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={`fixed md:static inset-y-0 left-0 w-64 bg-gray-900 text-white transform transition-transform duration-300 z-50 md:z-0 ${
          isOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'
        }`}
      >
        <nav className="p-4 space-y-2 h-full overflow-y-auto">
          {/* Nav Items */}
          {navItems.map((item) => (
            <button
              key={item.id}
              onClick={() => setCurrentPage(item.id)}
              className={`w-full flex items-center justify-between gap-3 px-4 py-3 rounded-lg transition-all group ${
                currentPage === item.id
                  ? 'bg-primary text-white'
                  : 'text-gray-400 hover:text-white hover:bg-gray-800'
              }`}
            >
              <div className="flex items-center gap-3">
                {item.icon}
                <span className="font-medium">{item.label}</span>
              </div>
              {item.badge && (
                <span className="bg-danger text-white text-xs rounded-full px-2 py-0.5 group-hover:scale-110 transition-transform">
                  {item.badge}
                </span>
              )}
            </button>
          ))}

          {/* Divider */}
          <div className="my-4 border-t border-gray-700" />

          {/* Settings */}
          <button className="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800 transition-all">
            <Settings size={20} />
            <span className="font-medium">Settings</span>
          </button>
        </nav>

        {/* Footer Info */}
        <div className="p-4 border-t border-gray-700 space-y-2">
          <p className="text-xs text-gray-500 font-medium">VERSION</p>
          <p className="text-sm text-gray-400">v2.0.0</p>
        </div>
      </aside>
    </>
  );
};
