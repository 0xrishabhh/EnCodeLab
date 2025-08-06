import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Activity } from 'lucide-react';
import Logo from './Logo';

const Navigation = () => {
  const location = useLocation();

  const navItems = [
    {
      path: '/',
      name: 'Home',
      description: 'Encryption & Decryption'
    },
    {
      path: '/benchmark',
      name: 'Benchmark',
      icon: Activity,
      description: 'Performance Analysis'
    }
  ];

  return (
    <nav className="bg-white shadow-sm border-b border-gray-200">
      <div className="px-6">
        <div className="flex items-center justify-between h-16">
          <div className="flex items-center space-x-8">
            <Link to="/" className="flex items-center hover:opacity-80 transition-opacity">
              <Logo />
            </Link>
            
            <div className="flex space-x-1">
              {navItems.map((item) => {
                const IconComponent = item.icon;
                const isActive = location.pathname === item.path;
                
                return (
                  <Link
                    key={item.path}
                    to={item.path}
                    className={`
                      flex items-center space-x-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors
                      ${isActive 
                        ? 'bg-primary-100 text-primary-700' 
                        : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                      }
                    `}
                  >
                    {IconComponent && <IconComponent className="w-4 h-4" />}
                    <span>{item.name}</span>
                  </Link>
                );
              })}
            </div>
          </div>
          
          <div className="flex items-center space-x-2 text-sm text-gray-500">
            <span>Learn, Test, and Compare Encryption Algorithms</span>
          </div>
        </div>
      </div>
    </nav>
  );
};

export default Navigation; 