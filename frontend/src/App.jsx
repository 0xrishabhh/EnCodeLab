import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Navigation from './components/Navigation';
import CryptoLabPage from './components/CryptoLabPage';
import BenchmarkPage from './components/BenchmarkPage';
import LogoShowcase from './components/LogoShowcase';

function App() {
  return (
    <Router>
      <div className="min-h-screen bg-gray-50">
        <Navigation />
        <Routes>
          <Route path="/" element={<CryptoLabPage />} />
          <Route path="/benchmark" element={<BenchmarkPage />} />
          <Route path="/logo-showcase" element={<LogoShowcase />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App; 