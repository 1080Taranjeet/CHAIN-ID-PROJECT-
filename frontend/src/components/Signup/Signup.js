// src/components/Signup/Signup.js
import React, { useState } from 'react';
import { Card, Button, Form } from 'react-bootstrap';
import { TextField } from '@mui/material';
import { useTheme as useMUITheme } from '@mui/material/styles';
import { FaFingerprint, FaCamera } from 'react-icons/fa'; // Import React Icons
import { useTheme } from '../../theme/ThemeContext'; // Import the theme context
import './Signup.css'; // Ensure to import the CSS file

const Signup = () => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    signupMethod: '',
  });
  const [isLogin, setIsLogin] = useState(false); // State to toggle between login and signup
  const { isDarkMode} = useTheme(); // Get the theme context
  const theme = useMUITheme(); // Get the MUI theme

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    // Handle form submission logic here
    alert(`Signup method: ${formData.signupMethod}`);
  };

  return (
    <div className={`signup-container ${isDarkMode ? 'dark' : 'light'}`}>
      <Card className="auth-card">
        <div className="form-section">
          <Card.Body>
            <h2 className="auth-title">{isLogin ? 'Login' : 'Create Account'}</h2>
            <Form onSubmit={handleSubmit}>
              {!isLogin && (
                <TextField
                  fullWidth
                  label="Name"
                  variant="outlined"
                  name="name"
                  value={formData.name}
                  onChange={handleChange}
                  className="mb-3"
                  size="small"
                  InputLabelProps={{
                    style: { color: theme.palette.text.primary },
                  }}
                  InputProps={{
                    style: { color: theme.palette.text.primary },
                  }}
                />
              )}
              <TextField
                fullWidth
                label="Email"
                variant="outlined"
                name="email"
                value={formData.email}
                onChange={handleChange}
                className="mb-3"
                size="small"
                InputLabelProps={{
                  style: { color: theme.palette.text.primary },
                }}
                InputProps={{
                  style: { color: theme.palette.text.primary },
                }}
              />
              {!isLogin && (
                <div className="signup-methods mb-3">
                  <Button 
                    variant={formData.signupMethod === 'face' ? 'primary' : 'outline-primary'} 
                    onClick={() => setFormData({ ...formData, signupMethod: 'face' })}
                    className="me-2"
                  >
                    <FaCamera /> Face Scan
                  </Button>
                  <Button 
                    variant={formData.signupMethod === 'fingerprint' ? 'primary' : 'outline-primary'} 
                    onClick={() => setFormData({ ...formData, signupMethod: 'fingerprint' })}
                  >
                    <FaFingerprint /> Fingerprint Scan
                  </Button>
                </div>
              )}
              <Button variant="primary" type="submit" className="w-100">
                {isLogin ? 'Login' : 'Sign Up'}
              </Button>
            </Form>
            <div className="toggle-form mt-3">
              <Button variant="link" onClick={() => setIsLogin(!isLogin)}>
                {isLogin ? 'Create an account' : 'Already have an account? Login'}
              </Button>
            </div>
          </Card.Body>
        </div>
        <div className="info-section">
          <h3>Welcome!</h3>
          <p>Join us to enjoy exclusive features and benefits.</p>
          <p>Choose your preferred method to sign up quickly and securely.</p>
          <p>We value your privacy and security.</p>
        </div>
      </Card>
    </div>
  );
};

export default Signup;