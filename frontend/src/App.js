import React from 'react';
import { ThemeProvider } from './theme/ThemeContext';
import Home from './components/Home/HOME';
import NavBar from './components/NavBar/Navbar';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import './styles.css';
import Signup from './components/Signup/Signup';
import FingerprintPage from './components/Signup/FingerprintPage';
import FaceScanPage from './components/Signup/FaceScanPage';

const App = () => {
  return (
    <ThemeProvider>
      <Router>
        <NavBar />
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/Signup" element={<Signup />} />
          <Route path="/fingerprint" element={<FingerprintPage />} />
          <Route path="/facescan" element={<FaceScanPage />} />
        </Routes>
      </Router>
    </ThemeProvider>
  );
};

export default App;