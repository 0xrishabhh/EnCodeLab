import React from 'react';

const Logo = ({ className = "w-8 h-8", showText = true, textSize = "text-xl" }) => {
  return (
    <div className="flex items-center space-x-3">
      {/* Logo Icon - Minimalistic Hexagonal Lock Design */}
      <div className={`${className} text-primary-600 relative`}>
        <svg 
          viewBox="0 0 32 32" 
          fill="none" 
          xmlns="http://www.w3.org/2000/svg"
          className="w-full h-full"
        >
          {/* Hexagonal Background */}
          <path 
            d="M8 6L16 2L24 6V10L28 12V20L24 22V26L16 30L8 26V22L4 20V12L8 10V6Z" 
            fill="currentColor" 
            fillOpacity="0.1"
            stroke="currentColor" 
            strokeWidth="1.5"
            strokeLinejoin="round"
          />
          
          {/* Lock Body */}
          <rect 
            x="11" 
            y="14" 
            width="10" 
            height="8" 
            fill="currentColor"
            rx="1"
          />
          
          {/* Lock Shackle */}
          <path 
            d="M13 14V12C13 10.3431 14.3431 9 16 9C17.6569 9 19 10.3431 19 12V14"
            stroke="currentColor" 
            strokeWidth="1.8"
            strokeLinecap="round"
            fill="none"
          />
          
          {/* Key Hole */}
          <circle 
            cx="16" 
            cy="17" 
            r="1.2" 
            fill="white"
          />
          <rect 
            x="15.4" 
            y="17.8" 
            width="1.2" 
            height="2" 
            fill="white"
            rx="0.6"
          />
          
          {/* Decorative Binary Dots */}
          <circle cx="6" cy="8" r="0.8" fill="currentColor" fillOpacity="0.4" />
          <circle cx="26" cy="8" r="0.8" fill="currentColor" fillOpacity="0.4" />
          <circle cx="6" cy="24" r="0.8" fill="currentColor" fillOpacity="0.4" />
          <circle cx="26" cy="24" r="0.8" fill="currentColor" fillOpacity="0.4" />
        </svg>
      </div>
      
      {/* Logo Text */}
      {showText && (
        <h1 className={`${textSize} font-bold text-gray-900`}>
          <span className="text-primary-600">En</span>
          <span className="text-gray-900">Code</span>
          <span className="text-primary-500 font-light">Lab</span>
        </h1>
      )}
    </div>
  );
};

// Compact version for favicon/small spaces
export const LogoIcon = ({ className = "w-6 h-6" }) => {
  return (
    <div className={`${className} text-primary-600`}>
      <svg 
        viewBox="0 0 24 24" 
        fill="none" 
        xmlns="http://www.w3.org/2000/svg"
        className="w-full h-full"
      >
        {/* Simplified hexagon with lock */}
        <path 
          d="M6 4L12 1L18 4V8L12 11L6 8V4Z" 
          fill="currentColor" 
          fillOpacity="0.2"
        />
        <path 
          d="M6 16L12 13L18 16V20L12 23L6 20V16Z" 
          fill="currentColor" 
          fillOpacity="0.2"
        />
        
        {/* Central lock */}
        <rect x="9" y="10" width="6" height="4" fill="currentColor" rx="0.5"/>
        <path 
          d="M10 10V9C10 7.89543 10.8954 7 12 7C13.1046 7 14 7.89543 14 9V10"
          stroke="currentColor" 
          strokeWidth="1.2"
          fill="none"
        />
        <circle cx="12" cy="11.5" r="0.8" fill="white"/>
      </svg>
    </div>
  );
};

// Loading animation version
export const LogoWithAnimation = ({ className = "w-8 h-8" }) => {
  return (
    <div className={`${className} text-primary-600 relative`}>
      <svg 
        viewBox="0 0 32 32" 
        fill="none" 
        xmlns="http://www.w3.org/2000/svg"
        className="w-full h-full"
      >
        {/* Animated outer ring */}
        <circle 
          cx="16" 
          cy="16" 
          r="14" 
          stroke="currentColor" 
          strokeWidth="1"
          strokeOpacity="0.2"
          fill="none"
          className="animate-spin"
          style={{
            strokeDasharray: '20 10',
            animationDuration: '3s'
          }}
        />
        
        {/* Hexagonal Background */}
        <path 
          d="M8 6L16 2L24 6V10L28 12V20L24 22V26L16 30L8 26V22L4 20V12L8 10V6Z" 
          fill="currentColor" 
          fillOpacity="0.1"
          stroke="currentColor" 
          strokeWidth="1.2"
        />
        
        {/* Lock */}
        <rect x="11" y="14" width="10" height="8" fill="currentColor" rx="1"/>
        <path 
          d="M13 14V12C13 10.3431 14.3431 9 16 9C17.6569 9 19 10.3431 19 12V14"
          stroke="currentColor" 
          strokeWidth="1.8"
          fill="none"
        />
        <circle cx="16" cy="17" r="1.2" fill="white"/>
        <rect x="15.4" y="17.8" width="1.2" height="2" fill="white" rx="0.6"/>
      </svg>
    </div>
  );
};

export default Logo;