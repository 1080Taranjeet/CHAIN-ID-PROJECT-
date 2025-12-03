import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { Card, Button } from 'react-bootstrap';
import { TextField, Grid, CircularProgress, Snackbar, Box, Paper, Typography, Fade, Zoom, Slide } from '@mui/material';
import MuiAlert from '@mui/material/Alert';
import { FaPaperPlane, FaCamera, FaFingerprint, FaShieldAlt, FaUserCheck } from 'react-icons/fa';
import { useTheme } from '../../theme/ThemeContext';
import { useForm } from 'react-hook-form';
import { yupResolver } from '@hookform/resolvers/yup';
import { useNavigate } from 'react-router-dom';
import * as yup from 'yup';
import axios from 'axios';
import CryptoJS from 'crypto-js';
import './login.css';
import BackgroundVideo from '../../theme/BackgroundVideo';
import { setSessionWithExpiry, getSessionWithExpiry } from '../../utils/sessionManager';
import FingerprintJS from '@fingerprintjs/fingerprintjs';
import { sha256 } from 'js-sha256';

// Validation schema for the form
const schema = yup.object().shape({
  email: yup.string().email('Invalid email').required('Email is required'),
  otp: yup.string().when('otpSent', (otpSent, schema) =>
    otpSent ? schema.required('OTP is required').length(6, 'OTP must be 6 digits') : schema
  ),
});

const Login = () => {
  const { isDarkMode } = useTheme();
  const [otpSent, setOtpSent] = useState(false);
  const [emailLocked, setEmailLocked] = useState(false);
  const [loading, setLoading] = useState({ send: false, verify: false, biometric: false });
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [otpExpiry, setOtpExpiry] = useState(0);
  const [attemptsLeft, setAttemptsLeft] = useState(5);
  const [timer, setTimer] = useState(0);
  const [openSnackbar, setOpenSnackbar] = useState(false);
  const [authMethods, setAuthMethods] = useState([]);
  const [emailExists, setEmailExists] = useState(false);
  const [emailVerified, setEmailVerified] = useState(false);
  const [activeMethod, setActiveMethod] = useState(null);

  const navigate = useNavigate();

  const { register, handleSubmit, setValue, watch, formState: { errors } } = useForm({
    resolver: yupResolver(schema),
    mode: 'onChange',
    defaultValues: { otpSent: false },
  });

  const ENCRYPTION_KEY = process.env.REACT_APP_ENCRYPTION_KEY || 'EVOd/1ytp2RnK9SSzfm6qYfY/FqtUopSi3+K/SeAAnk=';
  const APP_ORIGIN = window.location.origin;

  // Debounce utility
  function debounce(func, delay) {
    let timeoutId;
    return (...args) => {
      clearTimeout(timeoutId);
      timeoutId = setTimeout(() => func(...args), delay);
    };
  }

  // Encrypt data using AES
  const encryptData = useCallback((data) => {
    try {
      const key = CryptoJS.enc.Base64.parse(ENCRYPTION_KEY);
      const iv = CryptoJS.lib.WordArray.random(16);
      const encrypted = CryptoJS.AES.encrypt(JSON.stringify(data), key, { iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
      return `${CryptoJS.enc.Base64.stringify(iv)}:${encrypted.toString()}`;
    } catch (err) {
      console.error('Encryption Error:', err);
      throw new Error('Failed to encrypt data');
    }
  }, [ENCRYPTION_KEY]);

  // Check camera availability
  const checkCamera = useCallback(async () => {
    try {
      const devices = await navigator.mediaDevices.enumerateDevices();
      return devices.some(device => device.kind === 'videoinput');
    } catch (error) {
      console.error('Error checking camera:', error);
      return false;
    }
  }, []);

  // Get device ID
  const getDeviceID = useCallback(async () => {
    try {
      const fp = await FingerprintJS.load();
      const result = await fp.get();
      return sha256(result.visitorId);
    } catch (error) {
      console.error('Error getting device ID:', error);
      throw new Error('Failed to get device ID');
    }
  }, []);

  // Handle face login
  const handleFaceLogin = useCallback(async (imageData) => {
    try {
      setLoading(prev => ({ ...prev, biometric: true }));
      const deviceId = await getDeviceID();
      const encryptedSession = encryptData({
        email: watch('email'),
        deviceId,
        image: imageData
      });

      console.log('Sending face login request with encryptedSession:', encryptedSession);

      const response = await axios.post('http://localhost:5000/api/login-face', {
        encryptedSession
      });

      console.log('Face login response:', response.data);

      if (response.data.success) {
        setSessionWithExpiry('secureSession', {session_id: response.data.session_id, deviceId}, 7);
        setSuccess('Face login successful!');
        setOpenSnackbar(true);
        navigate('/User');
      } else {
        setError(response.data.message || 'Face login failed');
        setOpenSnackbar(true);
      }
    } catch (error) {
      console.error('Face login error:', error);
      setError(error.response?.data?.message || 'Face recognition error');
      setOpenSnackbar(true);
    } finally {
      setLoading(prev => ({ ...prev, biometric: false }));
    }
  }, [watch, getDeviceID, encryptData, navigate]);

  // Handle login (for OTP and fingerprint)
  const handleLogin = useCallback(async ({ email, method, biometricData = {} }) => {
    try {
      setLoading(prev => ({ ...prev, biometric: method !== 'otp' }));
      const deviceId = await getDeviceID();
      let payload = { email, deviceId };
      let endpoint = '/api/login';

      if (method === 'fingerprint') {
        payload.publicKey = biometricData.publicKey;
        endpoint = '/api/login-fingerprint';
      } else {
        payload.loginMethod = 'otp';
      }

      const encryptedSession = encryptData(payload);
      const res = await axios.post(`http://localhost:5000${endpoint}`, { encryptedSession }, { timeout: 10000 });

      if (res.data.success) {
        setSessionWithExpiry('secureSession', {session_id: res.data.session_id, deviceId}, 7);
        setSuccess(`${method.charAt(0).toUpperCase() + method.slice(1)} login successful!`);
        setOpenSnackbar(true);
        navigate('/User');
      } else {
        setError(res.data.message || `${method.charAt(0).toUpperCase() + method.slice(1)} login failed`);
        setOpenSnackbar(true);
      }
    } catch (error) {
      setError(`Error processing ${method} login: ${error.response?.data?.message || error.message}`);
      setOpenSnackbar(true);
    } finally {
      setLoading(prev => ({ ...prev, biometric: false }));
    }
  }, [encryptData, getDeviceID, navigate]);

  // Send OTP request
  const sendOtpRequest = useCallback(async () => {
    try {
      setLoading(prev => ({ ...prev, send: true }));
      const email = watch('email');
      const encrypted = encryptData({ email });
      const { data } = await axios.post('http://localhost:5000/send-otp',
        { encrypted_email: encrypted, purpose: 'login' },
        { timeout: 10000 }
      );

      setOtpExpiry(Math.floor(Date.now() / 1000) + data.expiry);
      setTimer(data.expiry);
      setAttemptsLeft(5);
      setOtpSent(true);
      setValue('otpSent', true);
      setSuccess('OTP sent successfully! Check your email.');
      setOpenSnackbar(true);
    } catch (err) {
      setError('Failed to send OTP: ' + (err.response?.data?.message || err.message));
      setOpenSnackbar(true);
    } finally {
      setLoading(prev => ({ ...prev, send: false }));
    }
  }, [watch, setValue, encryptData]);

  // Debounced send OTP
  const debouncedSendOtp = useMemo(() => debounce(sendOtpRequest, 500), [sendOtpRequest]);
  const handleSendOtp = useCallback(() => debouncedSendOtp(), [debouncedSendOtp]);

  // Check email existence
  const checkEmailRequest = useCallback(async () => {
    try {
      setLoading(prev => ({ ...prev, send: true }));
      setError('');
      const email = watch('email');
      const encrypted = encryptData({ email });
      const { data } = await axios.post('http://localhost:5000/api/check-email', { encrypted_email: encrypted }, { timeout: 10000 });

      if (data.exists) {
        setEmailExists(true);
        setEmailLocked(true);
        setSuccess('Email verified! Choose a login method.');
        setOpenSnackbar(true);

        const methods = data.signup_method;
        const methodsArray = [];
        if (methods === 'face') {
          methodsArray.push('face');
        } else if (methods === 'fingerprint') {
          methodsArray.push('fingerprint');
        } else if (methods === 'both') {
          methodsArray.push('fingerprint', 'face');
        }
        setAuthMethods(methodsArray);
      } else {
        setError('Email not found. Please sign up first.');
        setEmailExists(false);
        setAuthMethods([]);
      }
    } catch (err) {
      setError('Error checking email: ' + (err.response?.data?.message || err.message));
      setOpenSnackbar(true);
    } finally {
      setLoading(prev => ({ ...prev, send: false }));
    }
  }, [watch, encryptData]);

  const debouncedCheckEmail = useMemo(() => debounce(checkEmailRequest, 500), [checkEmailRequest]);
  const checkEmail = useCallback(() => debouncedCheckEmail(), [debouncedCheckEmail]);

  // Verify OTP
  const verifyOtpRequest = useCallback(async () => {
    try {
      setLoading(prev => ({ ...prev, verify: true }));
      const encrypted = encryptData({ email: watch('email') });
      const { data } = await axios.post('http://localhost:5000/verify-otp', { encrypted_email: encrypted, otp: watch('otp') }, { timeout: 10000 });

      if (data.success) {
        setEmailVerified(true);
        setValue('otpSent', false);
        await handleLogin({ email: watch('email'), method: 'otp' });
      } else {
        const attemptsLeftNew = watch('otp').length === 6 ? (data.message.match(/(\d+)/)?.[0] || attemptsLeft - 1) : attemptsLeft;
        setError(data.message || 'Invalid OTP');
        setAttemptsLeft(attemptsLeftNew);
        setOpenSnackbar(true);
      }
    } catch (err) {
      setError('Verification failed: ' + (err.response?.data?.message || err.message));
      setOpenSnackbar(true);
    } finally {
      setLoading(prev => ({ ...prev, verify: false }));
    }
  }, [watch, attemptsLeft, encryptData, setValue, handleLogin]);

  const debouncedVerifyOtp = useMemo(() => debounce(verifyOtpRequest, 500), [verifyOtpRequest]);
  const handleVerifyOtp = useCallback(() => debouncedVerifyOtp(), [debouncedVerifyOtp]);

  // Open scan window for biometric authentication
  const openScanWindow = useCallback(async (scanType) => {
    if (!emailExists) {
      setError('Please verify your email first.');
      setOpenSnackbar(true);
      return;
    }

    if (scanType === 'face' && !(await checkCamera())) {
      setError('Camera device is not available');
      setOpenSnackbar(true);
      return;
    }

    const url = scanType === 'face' ? '/facescan-login' : '/fingerprint-login';
    const width = scanType === 'face' ? 600 : 375;
    const height = scanType === 'face' ? 800 : 667;
    const left = (window.screen.width - width) / 2;
    const top = (window.screen.height - height) / 2;

    const email = encodeURIComponent(watch('email'));
    const scanUrl = `${APP_ORIGIN}${url}?email=${email}`;

    console.log(`Opening ${scanType} scan window at: ${scanUrl}`);

    const newWindow = window.open(
      scanUrl,
      '_blank',
      `width=${width},height=${height},left=${left},top=${top}`
    );

    if (!newWindow) {
      console.error('Failed to open popup window');
      setError('Failed to open authentication window. Please allow pop-ups.');
      setOpenSnackbar(true);
      return;
    }

    const messageHandler = async (event) => {
      console.log('Received message event:', {
        origin: event.origin,
        expectedOrigin: APP_ORIGIN,
        sourceMatches: event.source === newWindow,
        data: event.data
      });

      if (event.origin !== APP_ORIGIN) {
        console.warn('Received message from unexpected origin:', event.origin);
        return;
      }

      console.log('Processing message from scan window:', event.data);

      const data = event.data;
      if (data.type === 'face_scan' && data.status === 'success') {
        await handleFaceLogin(data.image);
      } else if (data.type === 'fingerprint_result' && data.status === 'success') {
        await handleLogin({
          email: watch('email'),
          method: 'fingerprint',
          biometricData: { publicKey: data.publicKey }
        });
      } else if (data.status === 'error') {
        setError(data.message || `Failed to process ${scanType} authentication`);
        setOpenSnackbar(true);
      }
      window.removeEventListener('message', messageHandler);
      if (!newWindow.closed) newWindow.close();
    };

    window.addEventListener('message', messageHandler);

    // Cleanup on window close
    const checkWindowClosed = setInterval(() => {
      if (newWindow.closed) {
        console.log('Scan window closed');
        clearInterval(checkWindowClosed);
        window.removeEventListener('message', messageHandler);
      }
    }, 500);
  }, [emailExists, watch, handleLogin, handleFaceLogin, checkCamera, APP_ORIGIN]);

  // Handle snackbar close
  const handleSnackbarClose = useCallback((event, reason) => {
    if (reason === 'clickaway') return;
    setOpenSnackbar(false);
    setError('');
    setSuccess('');
  }, []);

  // Update form value when otpSent changes
  useEffect(() => {
    setValue('otpSent', otpSent);
  }, [otpSent, setValue]);

  // Timer for OTP expiry
  useEffect(() => {
    let interval;
    if (otpSent && otpExpiry > 0 && !emailVerified) {
      interval = setInterval(() => {
        const timeLeft = Math.max(0, otpExpiry - Math.floor(Date.now() / 1000));
        setTimer(timeLeft);
        if (timeLeft <= 0) {
          clearInterval(interval);
          setOtpSent(false);
          setValue('otpSent', false);
          setEmailLocked(false);
          setError('OTP expired. Please request a new one.');
          setOpenSnackbar(true);
        }
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [otpSent, otpExpiry, emailVerified, setValue]);

  // Check for existing session on mount
  useEffect(() => {
    async function checkLogin() {
      const Session = getSessionWithExpiry('secureSession');
      if (Session) {
        const encryptedSession = encryptData(Session)
        try {
          const res = await axios.post('http://localhost:5000/api/verify-session', { encryptedSession }, { timeout: 10000 });
          if (res.data.success) {
            navigate('/User');
          } else {
            localStorage.removeItem('secureSession');
          }
        } catch (err) {
          localStorage.removeItem('secureSession');
        }
      }
    }
    checkLogin();
  }, [navigate]);

  return (
    <div className={`login-container ${isDarkMode ? 'dark' : 'light'}`}>
      <BackgroundVideo />
      <Snackbar 
        open={openSnackbar} 
        autoHideDuration={3000} 
        onClose={handleSnackbarClose}
        anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
        TransitionComponent={Slide}
      >
        <MuiAlert 
          elevation={6} 
          variant="filled" 
          onClose={handleSnackbarClose} 
          severity={error ? 'error' : 'success'}
          sx={{ 
            borderRadius: '12px',
            boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
            fontWeight: 500
          }}
        >
          {error || success}
        </MuiAlert>
      </Snackbar>

      <Fade in timeout={800}>
        <Card className={`auth-card-login ${isDarkMode ? 'dark-card' : 'light-card'}`}>
          <Card.Body className="card-body">
            <div className="security-header">
              <FaShieldAlt className="security-icon" />
              <h2 className="auth-title">Secure Login</h2>
            </div>
            
            <div className="form-container">
              <Grid container spacing={2} alignItems="center" className="mb-4">
                <Grid item xs={12} sm={8}>
                  <TextField
                    fullWidth
                    label="Email Address"
                    variant="outlined"
                    {...register('email')}
                    error={!!errors.email}
                    helperText={errors.email?.message}
                    disabled={emailLocked}
                    InputProps={{
                      style: { 
                        borderRadius: '12px',
                        backgroundColor: isDarkMode ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.03)',
                      }
                    }}
                    sx={{
                      '& .MuiOutlinedInput-root': {
                        '& fieldset': {
                          borderColor: isDarkMode ? '#444' : '#ddd',
                        },
                        '&:hover fieldset': {
                          borderColor: isDarkMode ? '#666' : '#aaa',
                        },
                        '&.Mui-focused fieldset': {
                          borderColor: '#1976d2',
                          borderWidth: 2,
                        },
                      }
                    }}
                  />
                </Grid>
                <Grid item xs={12} sm={4}>
                  <Button
                    variant={emailExists ? 'outline-success' : 'primary'}
                    onClick={checkEmail}
                    disabled={!!errors.email || !watch('email') || emailLocked || loading.send}
                    className="verify-button"
                  >
                    {loading.send ? (
                      <CircularProgress size={24} style={{ color: 'white' }} />
                    ) : emailExists ? (
                      <span className="verified-text">
                        <FaUserCheck className="mr-1" /> Verified
                      </span>
                    ) : (
                      'Verify Email'
                    )}
                  </Button>
                </Grid>
              </Grid>

              {emailExists && (
                <div className="auth-methods-container">
                  {!otpSent ? (
                    <Fade in timeout={500}>
                      <div>
                        <Typography variant="subtitle1" className="method-title">
                          Choose Authentication Method:
                        </Typography>
                        
                        <div className="method-grid">
                          <Zoom in style={{ transitionDelay: '100ms' }}>
                            <Paper 
                              elevation={3} 
                              className={`method-card ${activeMethod === 'otp' ? 'active' : ''}`}
                              onClick={handleSendOtp}
                            >
                              <div className="method-icon-container">
                                <FaPaperPlane className="method-icon" />
                              </div>
                              <Typography variant="body1" className="method-name">
                                OTP Verification
                              </Typography>
                              {loading.send && <CircularProgress size={24} className="method-loading" />}
                            </Paper>
                          </Zoom>

                          {authMethods.includes('face') && (
                            <Zoom in style={{ transitionDelay: '200ms' }}>
                              <Paper 
                                elevation={3} 
                                className={`method-card ${activeMethod === 'face' ? 'active' : ''}`}
                                onClick={() => {
                                  setActiveMethod('face');
                                  openScanWindow('face');
                                }}
                              >
                                <div className="method-icon-container">
                                  <FaCamera className="method-icon" />
                                </div>
                                <Typography variant="body1" className="method-name">
                                  Face Recognition
                                </Typography>
                                {loading.biometric && <CircularProgress size={24} className="method-loading" />}
                              </Paper>
                            </Zoom>
                          )}

                          {authMethods.includes('fingerprint') && (
                            <Zoom in style={{ transitionDelay: '300ms' }}>
                              <Paper 
                                elevation={3} 
                                className={`method-card ${activeMethod === 'fingerprint' ? 'active' : ''}`}
                                onClick={() => {
                                  setActiveMethod('fingerprint');
                                  openScanWindow('fingerprint');
                                }}
                              >
                                <div className="method-icon-container">
                                  <FaFingerprint className="method-icon" />
                                </div>
                                <Typography variant="body1" className="method-name">
                                  Fingerprint Scan
                                </Typography>
                                {loading.biometric && <CircularProgress size={24} className="method-loading" />}
                              </Paper>
                            </Zoom>
                          )}
                        </div>

                        {authMethods.length === 0 && (
                          <div className="no-methods-message">
                            Only OTP authentication available for this account
                          </div>
                        )}
                      </div>
                    </Fade>
                  ) : (
                    <Fade in timeout={500}>
                      <div className="otp-section">
                        <Typography variant="subtitle1" className="method-title">
                          Enter Your OTP:
                        </Typography>
                        
                        <Grid container spacing={2}>
                          <Grid item xs={12} sm={8}>
                            <TextField
                              fullWidth
                              label="One-Time Password"
                              variant="outlined"
                              {...register('otp')}
                              error={!!errors.otp}
                              helperText={errors.otp?.message}
                              inputProps={{ maxLength: 6 }}
                              InputProps={{
                                style: { 
                                  borderRadius: '12px',
                                  backgroundColor: isDarkMode ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.03)',
                                }
                              }}
                            />
                            <div className="otp-meta">
                              <span className={`timer ${timer > 0 ? 'active' : 'expired'}`}>
                                {timer > 0 ? `Expires in ${timer}s` : 'OTP Expired'}
                              </span>
                              <span className="attempts">
                                Attempts left: {attemptsLeft}
                              </span>
                            </div>
                          </Grid>
                          <Grid item xs={12} sm={4}>
                            <Button
                              variant="primary"
                              onClick={handleVerifyOtp}
                              disabled={!watch('otp') || watch('otp').length !== 6 || loading.verify}
                              className="verify-otp-button"
                            >
                              {loading.verify ? (
                                <CircularProgress size={24} style={{ color: 'white' }} />
                              ) : (
                                'Verify OTP'
                              )}
                            </Button>
                          </Grid>
                        </Grid>
                      </div>
                    </Fade>
                  )}
                </div>
              )}

              <div className="auth-footer">
                <Button
                  variant="link"
                  onClick={() => navigate('/signup')}
                  className="footer-link"
                >
                  New user? Create account
                </Button>
              </div>
            </div>
          </Card.Body>
        </Card>
      </Fade>
    </div>
  );
};

export default Login;