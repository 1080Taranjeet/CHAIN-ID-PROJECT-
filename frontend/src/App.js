
import { ThemeProvider } from './theme/ThemeContext';
import Home from './components/Home/HOME';
import NavBar from './components/NavBar/Navbar';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import './styles.css';
import Signup from './components/Signup/Signup';
import FingerprintPage from './components/Signup/FingerprintPage';
import FaceScanPage from './components/Signup/FaceScanPage';
import User from './components/User/user';
import Login from './components/Login/login';
import 'bootstrap/dist/js/bootstrap.bundle.min';
import 'bootstrap/dist/css/bootstrap.min.css';
import FingerprintLogin from './components/Login/FingerPrintLogin';
import FaceScanLogin from './components/Login/FaceScan';
import UserApi from './components/User/userApi';
import ContactUs from './components/ContactUs/ContactUS';
import AboutUs from './components/AboutUS/AboutUS';

const App = () => {
  return (
    <ThemeProvider>
      <Router>
        <NavBar />
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/Signup" element={<Signup />} />
          <Route path="/Login" element={<Login />} />
          <Route path="/fingerprint" element={<FingerprintPage />} />
          <Route path="/facescan" element={<FaceScanPage />} />
          <Route path="/User" element={<User/>} />
          <Route path="/fingerprint-login" element={<FingerprintLogin />} />
          <Route path="/facescan-login" element={<FaceScanLogin />} />
          <Route path="/User/api" element={<UserApi />} />
          <Route path="/contact" element={<ContactUs />} />
          <Route path="/about" element={<AboutUs/>} />
        </Routes>
      </Router>
    </ThemeProvider>
  );
};

export default App;