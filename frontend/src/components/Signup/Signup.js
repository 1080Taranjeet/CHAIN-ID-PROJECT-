import React, { useState, useEffect, useCallback } from 'react';
import { Link } from "react-router-dom";
import { Card, Button, Form, Alert } from 'react-bootstrap';
import { sha256 } from 'js-sha256';
import { TextField, Grid, Box, CircularProgress, Snackbar } from '@mui/material';
import MuiAlert from '@mui/material/Alert'; // For the Snackbar Alert
import { FaFingerprint, FaCamera, FaPaperPlane, FaCheckCircle } from 'react-icons/fa';
import { useTheme } from '../../theme/ThemeContext';
import { useForm } from 'react-hook-form';
import { yupResolver } from '@hookform/resolvers/yup';
import * as yup from 'yup';
import axios from 'axios';
import CryptoJS from 'crypto-js';
import './Signup.css';
import BackgroundVideo from '../../theme/BackgroundVideo';
import Slider from 'react-slick';
import 'slick-carousel/slick/slick.css';
import 'slick-carousel/slick/slick-theme.css';
import FingerprintJS from '@fingerprintjs/fingerprintjs';
import { setSessionWithExpiry, getSessionWithExpiry } from '../../utils/sessionManager';

// Simplified Yup schema
const schema = yup.object().shape({
  email: yup.string().email('Invalid email').required('Email is required'),
  otp: yup.string().when('otpSent', (otpSent, schema) =>
    otpSent ? schema.required('OTP is required').length(6, 'OTP must be 6 digits') : schema
  ),
  signupMethod: yup.string().oneOf(['face', 'fingerprint']).nullable(),
  faceData: yup.string().nullable(),
  fingerprintPublicKey: yup.string().nullable(),
  biometricConsent: yup.boolean().nullable(),
});

const Signup = () => {

  const checkLogin = async () => {
    const Session = getSessionWithExpiry('secureSession');

    if (Session) {
      const encryptedSession = encryptData(Session);
      try {
        const res = await axios.post('http://localhost:5000/api/verify-session', { encryptedSession });
        if (res.data.success) {
          window.location.href = '/User';
        } else {
          console.warn('Invalid session from backend.');
          localStorage.removeItem('secureSession');
        }
      } catch (err) {
        console.warn('Session invalid or expired:', err.message);
        localStorage.removeItem('secureSession');
      }
    } else {
      console.log('Session expired or not found on frontend.');
    }
  };

  useEffect(() => {
    checkLogin();
  }, []);

  const [isLogin, setIsLogin] = useState(false);
  const { isDarkMode } = useTheme();
  const [selectedMethod, setSelectedMethod] = useState(null);
  const [otpSent, setOtpSent] = useState(false);
  const [emailVerified, setEmailVerified] = useState(false);
  const [emailLocked, setEmailLocked] = useState(false);
  const [loading, setLoading] = useState({ send: false, verify: false });
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(''); // For Snackbar
  const [otpExpiry, setOtpExpiry] = useState(0);
  const [attemptsLeft, setAttemptsLeft] = useState(5);
  const [timer, setTimer] = useState(0);
  const [openSnackbar, setOpenSnackbar] = useState(false); // For controlling Snackbar visibility

  const { register, handleSubmit, setValue, watch, formState: { errors, isSubmitting } } = useForm({
    resolver: yupResolver(schema),
    mode: 'onChange',
    defaultValues: {
      biometricConsent: false,
      otpSent: false,
    },
  });

  const ENCRYPTION_KEY = process.env.REACT_APP_ENCRYPTION_KEY || 'EVOd/1ytp2RnK9SSzfm6qYfY/FqtUopSi3+K/SeAAnk=';

  useEffect(() => {
    setValue('otpSent', otpSent);
  }, [otpSent, setValue]);

  const debounce = (func, delay) => {
    let timeoutId;
    return (...args) => {
      clearTimeout(timeoutId);
      timeoutId = setTimeout(() => func(...args), delay);
    };
  };

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
        }
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [otpSent, otpExpiry, emailVerified]);

  const encryptData = (data) => {
    try {
      const key = CryptoJS.enc.Base64.parse(ENCRYPTION_KEY);
      const iv = CryptoJS.lib.WordArray.random(16);
      const encrypted = CryptoJS.AES.encrypt(JSON.stringify(data), key, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      });
      const ivBase64 = CryptoJS.enc.Base64.stringify(iv);
      const ciphertextBase64 = encrypted.toString();
      return `${ivBase64}:${ciphertextBase64}`;
    } catch (err) {
      console.error('Encryption Error:', err);
      throw new Error('Failed to encrypt data');
    }
  };

  const handleSendOtp = useCallback(debounce(async () => {
    if (isSubmitting) return;
    try {
      setLoading(prev => ({ ...prev, send: true }));
      setError('');
      const email = watch('email');
      const encrypted = encryptData({ email });

      const { data } = await axios.post(
        'http://localhost:5000/send-otp',
        { encrypted_email: encrypted , purpose: 'signup' },
        { timeout: 10000, headers: { 'Content-Type': 'application/json' } }
      ).catch(async (err) => {
        if (err.code === 'ECONNABORTED') {
          await new Promise(resolve => setTimeout(resolve, 2000));
          return axios.post('http://localhost:5000/send-otp', { encrypted_email: encrypted });
        }
        throw err;
      });

      const expiryTime = Math.floor(Date.now() / 1000) + data.expiry;
      setOtpExpiry(expiryTime);
      setTimer(data.expiry);
      setAttemptsLeft(5);
      setOtpSent(true);
      setValue('otpSent', true);
      setEmailLocked(true);
      setEmailVerified(false);
      setSuccess('OTP sent successfully! Check your email.');
    } catch (err) {
      setError('Failed to send OTP. ' + err.response.data.error);
      console.error('OTP Error:', err.response.data.error);
    } finally {
      setLoading(prev => ({ ...prev, send: false }));
    }
  }, 500), [watch, isSubmitting, setValue]);

  const handleVerifyOtp = useCallback(debounce(async () => {
    if (isSubmitting) return;
    try {
      setLoading(prev => ({ ...prev, verify: true }));
      setError('');
      const encrypted = encryptData({ email: watch('email') });

      const { data } = await axios.post(
        'http://localhost:5000/verify-otp',
        { encrypted_email: encrypted, otp: watch('otp') },
        { timeout: 10000, headers: { 'Content-Type': 'application/json' } }
      );

      if (data.success) {
        setEmailVerified(true);
        setValue('otpSent', false);
        setSuccess('Email verified successfully!');
        setAttemptsLeft(5); // Reset attempts on success
      } else {
        // Extract attempts left from message, e.g., "Incorrect OTP. 4 attempts left"
        const attemptsMatch = data.message.match(/(\d+) attempts left/);
        const attemptsLeftNew = attemptsMatch ? parseInt(attemptsMatch[1], 10) : attemptsLeft - 1;
        setError(data.message || 'Invalid OTP');
        setAttemptsLeft(attemptsLeftNew);
      }
    } catch (err) {
      setError('Verification failed. Please try again.');
      console.error('Verification Error:', err);
    } finally {
      setLoading(prev => ({ ...prev, verify: false }));
    }
  }, 500), [watch, attemptsLeft, isSubmitting, setValue]);

  const openScanWindow = async (scanType) => {
    if (!emailVerified) {
      alert('Please verify your email first');
      return;
    }
    if (!watch('biometricConsent')) {
      alert('Please consent to biometric data usage before proceeding.');
      return;
    }

    setSelectedMethod(scanType);

    if (scanType === 'face' && !(await checkCamera())) {
      alert('Camera device is not available');
      return;
    }

    const url = scanType === 'face' ? '/facescan' : '/fingerprint';
    const width = 375;
    const height = 667;
    const left = (window.screen.width - width) / 2;
    const top = (window.screen.height - height) / 2;

    const scanUrl = `${url}?email=${encodeURIComponent(watch('email'))}`;

    const newWindow = window.open(
      scanUrl,
      '_blank',
      `width=${width},height=${height},left=${left},top=${top}`
    );

    const messageHandler = (event) => {
      if (event.source === newWindow) {
        const data = event.data;
        console.log(data);
        if (data.type === 'fingerprint_result') {
          if (data.status === 'success') {
            setValue('signupMethod', 'fingerprint');
            setValue('fingerprintPublicKey', data.publicKey.id);
            setValue('biometricData', data.biometricData); // Triggers button state change
          } else {
            setError('Fingerprint registration failed: ' + data.error);
          }
        } else if (data.type === 'face_scan') {
          setValue('signupMethod', 'face');
          setValue('faceData', data.data);
        }
        newWindow.close();
        window.removeEventListener('message', messageHandler);
      }
    };
    window.addEventListener('message', messageHandler);
  };

  const checkCamera = async () => {
    try {
      const devices = await navigator.mediaDevices.enumerateDevices();
      return devices.some(device => device.kind === 'videoinput');
    } catch (error) {
      console.error('Error checking camera:', error);
      return false;
    }
  };

  const getDeviceID = async () => {
    const fp = await FingerprintJS.load();
    const result = await fp.get();
    const visitorId = result.visitorId;
    // Hash visitorId to get a 64-character hex string
    return sha256(visitorId);
  };

  const onSubmit = async (data) => {
    console.log('onSubmit triggered');
    console.log('Form Data:', data);
    console.log('Form Errors:', errors);

    const deviceId = await getDeviceID();
    console.log('Generated Device ID:', deviceId);

    const email = data?.email;

    // Set method to 'both' if both biometrics exist
    let signupMethod = data.signupMethod;
    const hasFace = !!data.faceData;
    const hasFingerprint = !!data.fingerprintPublicKey;

    if (hasFace && hasFingerprint) {
      signupMethod = 'both';
    } else if (hasFace) {
      signupMethod = 'face';
    } else if (hasFingerprint) {
      signupMethod = 'fingerprint';
    } else {
      signupMethod = 'none';
    }

    const payload = { email, deviceId, signupMethod };
    const encryptedSession = encryptData(payload);

    try {
      const result = {
        email,
        biometrics: {
          method: signupMethod,
          data: hasFace || hasFingerprint
            ? {
              ...(hasFace && { faceData: data.faceData }),
              ...(hasFingerprint && { publicKey: data.fingerprintPublicKey }),
            }
            : null,
        },
      };

      console.log('Signup Data:', JSON.stringify(result, null, 2));

      const answer = encryptData(result);

      const res = await axios.post('http://localhost:5000/api/register', { encryptedSession, answer });

      if (res.data.success) {
        setSessionWithExpiry('secureSession', {session_id: res.data.session_id, deviceId}, 7); // 7 days
        setSuccess('Signup successful!');
        setOpenSnackbar(true);
        window.location.href = '/User';
      } else {
        setError(res.data.message || 'Registration failed');
      }
    } catch (error) {
      setError('Error processing signup: ' + (error.response?.data?.message || error.message));
      console.error('Signup Error:', error);
    }
  };

  const handleSnackbarClose = (event, reason) => {
    if (reason === 'clickaway') {
      return;
    }
    setOpenSnackbar(false);
  };

  const settings = {
    dots: true,
    infinite: true,
    speed: 500,
    slidesToShow: 1,
    slidesToScroll: 1,
    autoplay: true,
    autoplaySpeed: 3000,
    arrows: false,
  };

  useEffect(() => {
    setValue('otpSent', otpSent);
  }, [otpSent, setValue]);

  return (
    <div className={`signup-container ${isDarkMode ? 'dark' : 'light'}`}>
      <BackgroundVideo />
      {/* Snackbar for success message */}
      <Snackbar
        open={openSnackbar}
        autoHideDuration={3000} // Auto-hide after 3 seconds
        onClose={handleSnackbarClose}
        anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
      >
        <MuiAlert
          elevation={6}
          variant="filled"
          onClose={handleSnackbarClose}
          severity="success"
        >
          {success}
        </MuiAlert>
      </Snackbar>

      <Card className="auth-card row">
        <div className="form-section p-5 col-6">
          <Card.Body>
            <h2 className="auth-title">{isLogin ? 'Login' : 'Create Account'}</h2>
            {error && <Alert variant="danger" className="mb-3">{error}</Alert>}
            {!error && success && !openSnackbar && (
              <Alert variant="success" className="mb-3">{success}</Alert>
            )}

            <Form onSubmit={handleSubmit(onSubmit)} noValidate>
              <Grid container spacing={2} alignItems="center" className="mb-3">
                <Grid item xs={8}>
                  <TextField
                    fullWidth
                    label="Email"
                    variant="outlined"
                    {...register('email')}
                    size="small"
                    error={!!errors.email}
                    helperText={errors.email?.message}
                    disabled={emailLocked}
                    inputProps={{ 'aria-label': 'Email address' }}
                  />
                </Grid>
                <Grid item xs={4}>
                  <Button
                    variant={otpSent ? 'outline-secondary' : 'outline-primary'}
                    onClick={handleSendOtp}
                    disabled={!!errors.email || !watch('email') || emailLocked || loading.send || isSubmitting}
                    className="w-100"
                    aria-label={otpSent ? 'OTP Sent' : 'Send OTP'}
                  >
                    {loading.send ? (
                      <CircularProgress size={20} color="inherit" />
                    ) : (
                      <>
                        <FaPaperPlane className="me-2" />
                        {otpSent ? 'Sent' : 'Send'}
                      </>
                    )}
                  </Button>
                </Grid>
              </Grid>

              {otpSent && !emailVerified && (
                <Grid container spacing={2} alignItems="center" className="mb-3">
                  <Grid item xs={8}>
                    <Box>
                      <TextField
                        fullWidth
                        label="OTP"
                        variant="outlined"
                        size="small"
                        {...register('otp')}
                        error={!!errors.otp}
                        helperText={errors.otp?.message}
                        inputProps={{ maxLength: 6, 'aria-label': 'One-Time Password' }}
                      />
                      <div className="d-flex justify-content-between mt-1">
                        <small className={`text-${timer > 0 ? 'muted' : 'danger'}`}>
                          {timer > 0 ? `Expires in: ${timer}s` : 'OTP expired'}
                        </small>
                        <small className="text-muted">
                          Attempts left: {attemptsLeft}
                        </small>
                      </div>
                    </Box>
                  </Grid>
                  <Grid item xs={4}>
                    <Button
                      variant={emailVerified ? 'outline-success' : 'outline-primary'}
                      onClick={handleVerifyOtp}
                      disabled={!watch('otp') || watch('otp').length !== 6 || loading.verify || timer <= 0 || attemptsLeft <= 0 || isSubmitting}
                      className="w-100 mb-3"
                      aria-label={emailVerified ? 'OTP Verified' : 'Verify OTP'}
                    >
                      {loading.verify ? (
                        <CircularProgress size={20} color="inherit" />
                      ) : (
                        <>
                          <FaCheckCircle className="me-2" />
                          {emailVerified ? 'Done' : 'Verify'}
                        </>
                      )}
                    </Button>
                  </Grid>
                </Grid>
              )}

              {!isLogin && emailVerified && (
                <div>
                  <div className="col-12 mb-3 text-center h5">Add Biometric Login (Optional)</div>
                  <Form.Check
                    type="checkbox"
                    label="I consent to the use of biometric data for authentication"
                    {...register('biometricConsent')}
                    className="mb-3"
                    isInvalid={!!errors.biometricConsent}
                  />
                  {errors.biometricConsent && (
                    <small className="text-danger">{errors.biometricConsent.message}</small>
                  )}
                  <div className="signup-methods mb-3">
                    <Button
                      variant={watch('faceData') ? 'primary' : 'outline-primary'}
                      onClick={() => openScanWindow('face')}
                      className="me-2"
                      disabled={!watch('biometricConsent')}
                      aria-label={watch('faceData') ? 'Face Added' : 'Add Face'}
                    >
                      <FaCamera /> {watch('faceData') ? 'Face Added' : 'Add Face'}
                    </Button>
                    <Button
                      variant={
                        watch('biometricData') && watch('signupMethod') === 'fingerprint'
                          ? 'success' // Change to success when biometricData is received
                          : 'outline-primary'
                      }
                      onClick={() => openScanWindow('fingerprint')}
                      disabled={!watch('biometricConsent')}
                      aria-label={
                        watch('biometricData') && watch('signupMethod') === 'fingerprint'
                          ? 'Fingerprint Added'
                          : 'Add Fingerprint'
                      }
                    >
                      <FaFingerprint />{' '}
                      {watch('biometricData') && watch('signupMethod') === 'fingerprint'
                        ? 'Fingerprint Added'
                        : 'Add Fingerprint'}
                    </Button>
                  </div>
                </div>
              )}

              <Button
                variant="primary"
                type="submit"
                className="w-100 mt-3"
                disabled={!emailVerified || isSubmitting}
                aria-label={isLogin ? 'Login' : 'Sign Up'}
              >
                {isLogin ? 'Login' : 'Sign Up'}
              </Button>
              {Object.keys(errors).length > 0 && (
                <Alert variant="danger">
                  Form Errors:
                  <ul>
                    {Object.entries(errors).map(([field, error]) => (
                      <li key={field}>
                        {field}: {error.message}
                      </li>
                    ))}
                  </ul>
                </Alert>
              )}
            </Form>
            <div className="toggle-form mt-3">
              <Link to={'/login'}>
                <Button variant="link" aria-label="Toggle Login/Signup">
                  {isLogin ? 'Create an account' : 'Already have an account? Login'}
                </Button>
              </Link>
            </div>
          </Card.Body>
        </div>
        <div className="info-section col-6">
          <div style={{ width: '100%', maxWidth: '800px' }}>
            <Slider {...settings}>
              <div className="d-flex py-5 px-3 flex-column justify-content-center">
                <h3>Welcome!</h3>
                <p>Join us to enjoy exclusive features and benefits.</p>
              </div>
              <div className="d-flex flex-column py-5 px-3 justify-content-center">
                <h3>Fast & Secure</h3>
                <p>Sign up using Face Recognition or Fingerprint Scan.</p>
              </div>
              <div className="d-flex flex-column py-5 px-3 justify-content-center">
                <h3>Your Data is Safe</h3>
                <p>We prioritize security and privacy in all our processes.</p>
              </div>
            </Slider>
          </div>
        </div>
      </Card>
    </div>
  );
};

export default Signup;