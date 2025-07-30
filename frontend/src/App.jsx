import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Navigation from './components/Navigation';
import CryptoLabPage from './components/CryptoLabPage';
import BenchmarkPage from './components/BenchmarkPage';

function App() {
  return (
    <Router>
      <div className="min-h-screen bg-gray-50">
        <Navigation />
        <Routes>
          <Route path="/" element={<CryptoLabPage />} />
          <Route path="/benchmark" element={<BenchmarkPage />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App; 