import React, { useState, useEffect, useCallback } from 'react';
import { Box, Button, Typography, CircularProgress, Snackbar } from '@mui/material';
import { Fingerprint } from '@mui/icons-material';
import { motion } from 'framer-motion';
import MuiAlert from '@mui/material/Alert';
import axios from 'axios';
import CryptoJS from 'crypto-js';
import FingerprintJS from '@fingerprintjs/fingerprintjs';
import { sha256 } from 'js-sha256';

const API_BASE = process.env.REACT_APP_API_BASE_URL || 'http://localhost:5000';
const ENCRYPTION_KEY = process.env.REACT_APP_ENCRYPTION_KEY || 'EVOd/1ytp2RnK9SSzfm6qYfY/FqtUopSi3+K/SeAAnk=';

// AES encryption helper
const encryptData = data => {
  try {
    const key = CryptoJS.enc.Base64.parse(ENCRYPTION_KEY);
    const iv = CryptoJS.lib.WordArray.random(16);
    const encrypted = CryptoJS.AES.encrypt(JSON.stringify(data), key, {
      iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    });
    return `${CryptoJS.enc.Base64.stringify(iv)}:${encrypted.toString()}`;
  } catch (err) {
    console.error('Encryption Error:', err);
    throw new Error('Failed to encrypt data');
  }
};

// Decode base64url to ArrayBuffer, adding padding for atob compatibility
const decodeBase64 = input => {
  try {
    let str = input.replace(/-/g, '+').replace(/_/g, '/');
    const padding = str.length % 4;
    if (padding) {
      str += '='.repeat(4 - padding);
    }
    const binary = window.atob(str);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch (err) {
    console.error('Base64 Decode Error:', err);
    throw new Error('Invalid base64 string');
  }
};

const FingerprintLogin = () => {
  const [loading, setLoading] = useState(false);
  const [isSupported, setIsSupported] = useState(true);
  const [error, setError] = useState('');
  const [openSnackbar, setOpenSnackbar] = useState(false);

  // Extract email from URL
  const params = new URLSearchParams(window.location.search);
  const email = params.get('email') || '';

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

  // Hide navbar
  useEffect(() => {
    const nav = document.querySelector('.navbar');
    if (nav) nav.style.display = 'none';
    return () => nav && (nav.style.display = '');
  }, []);

  // Check WebAuthn support
  useEffect(() => {
    if (!window.PublicKeyCredential) {
      setIsSupported(false);
      setError('Fingerprint authentication not supported by this browser.');
      setOpenSnackbar(true);
      return;
    }

    window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
      .then(available => {
        if (!available) {
          setIsSupported(false);
          setError('Device fingerprint sensor not available.');
          setOpenSnackbar(true);
        }
      })
      .catch(err => {
        console.error('WebAuthn availability check failed:', err);
        setIsSupported(false);
        setError('Failed to check fingerprint sensor availability.');
        setOpenSnackbar(true);
      });
  }, []);

  const handleClose = (_, reason) => {
    if (reason === 'clickaway') return;
    setOpenSnackbar(false);
    setError('');
  };

  // Strict biometric verification
  const verifyBiometricResponse = (assertion) => {
    try {
      if (assertion.authenticatorAttachment !== 'platform') {
        throw new Error('External security keys not allowed');
      }
      if (assertion.response.authenticatorData) {
        const authData = new Uint8Array(assertion.response.authenticatorData);
        const flags = authData[32];
        const uvFlag = (flags & 0x04) !== 0;
        if (!uvFlag) {
          throw new Error('Biometric verification not performed');
        }
      }
    } catch (err) {
      console.error('Biometric verification error:', err);
      throw err;
    }
  };

  const handleScan = useCallback(async () => {
    if (!email) {
      setError('Missing email address.');
      setOpenSnackbar(true);
      return;
    }

    setLoading(true);
    try {
      // Step 1: Get fingerprint ID from backend
      const encryptedEmail = encryptData({ email });
      const { data } = await axios.post(`${API_BASE}/api/get-fingerprint-id`, {
        encrypted_email: encryptedEmail
      }, { timeout: 10000 });

      if (!data.success) {
        throw new Error(data.message || 'Failed to retrieve fingerprint ID');
      }

      const fingerprintId = data.fingerprint_id;
      if (!fingerprintId) {
        throw new Error('No fingerprint ID found');
      }

      // Step 2: Generate challenge and request WebAuthn assertion
      const challenge = crypto.getRandomValues(new Uint8Array(32));
      const publicKeyOptions = {
        challenge: challenge.buffer,
        rpId: window.location.hostname || 'localhost',
        allowCredentials: [{
          type: 'public-key',
          id: decodeBase64(fingerprintId),
          transports: ['internal'],
        }],
        userVerification: 'required',
        timeout: 60000,
      };

      const assertion = await navigator.credentials.get({ publicKey: publicKeyOptions });

      // Step 3: Verify biometric response
      verifyBiometricResponse(assertion);

      // Step 4: Use assertion.id as publicKey (base64url-encoded)
      const publicKey = assertion.id;

      // Step 5: Notify Login page
      window.opener.postMessage(
        {
          type: 'fingerprint_result',
          status: 'success',
          publicKey: publicKey,
        },
        window.location.origin
      );
      setTimeout(() => window.close(), 300);
    } catch (err) {
      console.error('Fingerprint authentication error:', err);
      setError(`Authentication failed: ${err.message}`);
      setOpenSnackbar(true);
    } finally {
      setLoading(false);
    }
  }, [email]);

  return (
    <Box sx={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', bgcolor: 'background.default', p: 3 }}>
      <motion.div initial={{ opacity: 0, y: -50 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
        <Box sx={{ bgcolor: 'background.paper', borderRadius: 4, p: 4, boxShadow: 3, textAlign: 'center', maxWidth: 360, width: '100%' }}>
          <Typography variant="h5" color="primary" gutterBottom>
            Fingerprint Login
          </Typography>
          <Typography variant="body2" color="text.secondary" mb={2}>
            {email ? `Authenticating ${email}` : 'Email is missing'}
          </Typography>
          {!isSupported ? (
            <Typography color="error">Fingerprint authentication not supported</Typography>
          ) : (
            <>
              <motion.div animate={{ scale: loading ? [1, 1.1, 1] : 1 }} transition={{ repeat: loading ? Infinity : 0, duration: 0.6 }}>
                <Fingerprint sx={{ fontSize: 80, color: loading ? 'primary.main' : 'grey.400', mb: 2 }} />
              </motion.div>
              <Button
                variant="contained"
                onClick={handleScan}
                disabled={loading || !email}
                startIcon={loading ? <CircularProgress size={20} color="inherit" /> : null}
                sx={{ textTransform: 'none', borderRadius: 2, py: 1.5, width: '100%' }}
              >
                {loading ? 'Scanning...' : 'Scan Fingerprint'}
              </Button>
            </>
          )}
        </Box>
      </motion.div>
      <Snackbar open={openSnackbar} autoHideDuration={3000} onClose={handleClose}>
        <MuiAlert onClose={handleClose} severity="error" sx={{ width: '100%' }}>
          {error}
        </MuiAlert>
      </Snackbar>
    </Box>
  );
};

export default FingerprintLogin;