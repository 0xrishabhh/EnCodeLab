import React from 'react';
import Logo, { LogoIcon, LogoWithAnimation } from './Logo';

const LogoShowcase = () => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-blue-50 p-8">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-4xl font-bold text-gray-900 mb-2 text-center">
          EnCode Lab Logo Showcase
        </h1>
        <p className="text-gray-600 text-center mb-12">
          Minimalistic, secure, and professional logo design
        </p>

        {/* Main Logo Variations */}
        <div className="grid md:grid-cols-2 gap-8 mb-12">
          {/* Default Logo */}
          <div className="bg-white rounded-xl p-8 shadow-lg border border-gray-100">
            <h3 className="text-lg font-semibold mb-4 text-gray-700">Default Logo</h3>
            <div className="flex items-center justify-center py-8">
              <Logo />
            </div>
            <p className="text-sm text-gray-500 text-center">
              Primary logo with full text and icon
            </p>
          </div>

          {/* Large Logo */}
          <div className="bg-white rounded-xl p-8 shadow-lg border border-gray-100">
            <h3 className="text-lg font-semibold mb-4 text-gray-700">Large Logo</h3>
            <div className="flex items-center justify-center py-8">
              <Logo className="w-12 h-12" textSize="text-3xl" />
            </div>
            <p className="text-sm text-gray-500 text-center">
              Hero section or landing page version
            </p>
          </div>

          {/* Icon Only */}
          <div className="bg-white rounded-xl p-8 shadow-lg border border-gray-100">
            <h3 className="text-lg font-semibold mb-4 text-gray-700">Icon Only</h3>
            <div className="flex items-center justify-center py-8">
              <Logo showText={false} className="w-16 h-16" />
            </div>
            <p className="text-sm text-gray-500 text-center">
              Favicon or compact spaces
            </p>
          </div>

          {/* Compact Icon */}
          <div className="bg-white rounded-xl p-8 shadow-lg border border-gray-100">
            <h3 className="text-lg font-semibold mb-4 text-gray-700">Compact Icon</h3>
            <div className="flex items-center justify-center py-8">
              <LogoIcon className="w-12 h-12" />
            </div>
            <p className="text-sm text-gray-500 text-center">
              Simplified version for small spaces
            </p>
          </div>
        </div>

        {/* Animation Demo */}
        <div className="bg-white rounded-xl p-8 shadow-lg border border-gray-100 mb-12">
          <h3 className="text-lg font-semibold mb-4 text-gray-700">Animated Logo</h3>
          <div className="flex items-center justify-center py-8">
            <LogoWithAnimation className="w-16 h-16" />
          </div>
          <p className="text-sm text-gray-500 text-center">
            Loading animation with rotating ring
          </p>
        </div>

        {/* Color Variations */}
        <div className="bg-white rounded-xl p-8 shadow-lg border border-gray-100 mb-12">
          <h3 className="text-lg font-semibold mb-6 text-gray-700">Color Variations</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
            {/* Dark Background */}
            <div className="bg-gray-900 rounded-lg p-4 flex flex-col items-center">
              <div className="text-white">
                <Logo className="w-10 h-10" />
              </div>
              <span className="text-xs text-gray-300 mt-2">Dark Theme</span>
            </div>

            {/* Blue Background */}
            <div className="bg-blue-600 rounded-lg p-4 flex flex-col items-center">
              <div className="text-white">
                <Logo className="w-10 h-10" />
              </div>
              <span className="text-xs text-blue-100 mt-2">Blue Theme</span>
            </div>

            {/* Green Background */}
            <div className="bg-green-600 rounded-lg p-4 flex flex-col items-center">
              <div className="text-white">
                <Logo className="w-10 h-10" />
              </div>
              <span className="text-xs text-green-100 mt-2">Success Theme</span>
            </div>

            {/* Gradient Background */}
            <div className="bg-gradient-to-br from-purple-600 to-blue-600 rounded-lg p-4 flex flex-col items-center">
              <div className="text-white">
                <Logo className="w-10 h-10" />
              </div>
              <span className="text-xs text-purple-100 mt-2">Gradient</span>
            </div>
          </div>
        </div>

        {/* Size Guide */}
        <div className="bg-white rounded-xl p-8 shadow-lg border border-gray-100">
          <h3 className="text-lg font-semibold mb-6 text-gray-700">Size Guide</h3>
          <div className="space-y-6">
            <div className="flex items-center justify-between py-2 border-b border-gray-100">
              <Logo className="w-6 h-6" textSize="text-sm" />
              <span className="text-sm text-gray-500">Small (24px) - Mobile navigation</span>
            </div>
            <div className="flex items-center justify-between py-2 border-b border-gray-100">
              <Logo className="w-8 h-8" textSize="text-base" />
              <span className="text-sm text-gray-500">Medium (32px) - Desktop navigation</span>
            </div>
            <div className="flex items-center justify-between py-2 border-b border-gray-100">
              <Logo className="w-12 h-12" textSize="text-xl" />
              <span className="text-sm text-gray-500">Large (48px) - Headers</span>
            </div>
            <div className="flex items-center justify-between py-2">
              <Logo className="w-16 h-16" textSize="text-2xl" />
              <span className="text-sm text-gray-500">XL (64px) - Hero sections</span>
            </div>
          </div>
        </div>

        {/* Usage Guidelines */}
        <div className="mt-12 bg-blue-50 rounded-xl p-6 border border-blue-100">
          <h3 className="text-lg font-semibold mb-4 text-blue-900">Usage Guidelines</h3>
          <div className="grid md:grid-cols-2 gap-4 text-sm text-blue-800">
            <div>
              <h4 className="font-medium mb-2">✅ Do:</h4>
              <ul className="space-y-1 list-disc list-inside">
                <li>Use on white or light backgrounds</li>
                <li>Maintain aspect ratio when scaling</li>
                <li>Keep minimum 16px clear space around logo</li>
                <li>Use PNG/SVG for digital applications</li>
              </ul>
            </div>
            <div>
              <h4 className="font-medium mb-2">❌ Don't:</h4>
              <ul className="space-y-1 list-disc list-inside">
                <li>Stretch or distort the logo</li>
                <li>Use on busy or low-contrast backgrounds</li>
                <li>Add effects, shadows, or outlines</li>
                <li>Change colors without purpose</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LogoShowcase;