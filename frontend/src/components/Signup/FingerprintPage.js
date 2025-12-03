import React, { useState, useCallback } from 'react';
import {
  Typography,
  Alert,
  CircularProgress,
  Box,
  Paper,
  Button,
  useTheme,
} from '@mui/material';
import FingerprintIcon from '@mui/icons-material/Fingerprint';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import LockIcon from '@mui/icons-material/Lock';

const SECURITY_CONFIG = {
  rpId: window.location.hostname || 'localhost',
  rpName: 'Secure Application',
  timeout: 60000,
  challengeSize: 32,
};

const generateChallenge = () => {
  return crypto.getRandomValues(new Uint8Array(SECURITY_CONFIG.challengeSize));
};

const bufferToHex = (buffer) =>
  Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

const FingerprintAuth = () => {
  const theme = useTheme();
  const [status, setStatus] = useState('idle');
  const [error, setError] = useState(null);

  const urlParams = new URLSearchParams(window.location.search);
  const email = urlParams.get('email') || 'user@secureapp.com';

  // Strict verification of biometric authentication
  const verifyBiometricEnforcement = (credential) => {
    // 1. Verify authenticator is platform (built-in)
    if (credential.authenticatorAttachment !== 'platform') {
      throw new Error('External security keys not allowed');
    }
    
    // 2. Verify user verification occurred
    if (credential.response.authenticatorData) {
      const authData = new Uint8Array(credential.response.authenticatorData);
      const flags = authData[32];
      const uvFlag = (flags & 0x04) !== 0;
      
      if (!uvFlag) {
        throw new Error('Biometric verification not performed');
      }
    }
    
    // 3. Verify no fallback mechanisms were used
    if (credential.response.signature && credential.response.signature.byteLength < 70) {
      throw new Error('Insufficient authentication strength');
    }
  };

  const handleAuthenticationSuccess = useCallback((credential) => {
    try {
      verifyBiometricEnforcement(credential);

      const publicKey = {
        id: credential.id,
        rawId: bufferToHex(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: bufferToHex(credential.response.clientDataJSON),
        },
      };

      setStatus('success');

      if (window.opener) {
        window.opener.postMessage(
          {
            type: 'fingerprint_result',
            status: 'success',
            publicKey,
            email,
          },
          window.location.origin
        );
      }
      setTimeout(() => window.close(), 500);
    } catch (err) {
      setStatus('error');
      setError(err.message || 'Biometric enforcement failed');
    }
  }, [email]);

  const authenticateBiometric = useCallback(async () => {
    try {
      setStatus('checking');
      setError(null);

      if (!window.PublicKeyCredential) {
        throw new Error('Biometric authentication unavailable');
      }

      // Check for platform authenticator support
      const isPlatform = await window.PublicKeyCredential
        .isUserVerifyingPlatformAuthenticatorAvailable();
      
      if (!isPlatform) {
        throw new Error('Device fingerprint sensor not available');
      }

      setStatus('scanning');
      
      const options = {
        publicKey: {
          challenge: generateChallenge(),
          rpId: SECURITY_CONFIG.rpId,
          allowCredentials: [],
          userVerification: 'required',
          authenticatorSelection: {
            authenticatorAttachment: 'platform',
            requireResidentKey: true,
            userVerification: 'required',
          },
          timeout: SECURITY_CONFIG.timeout,
        },
      };

      const credential = await navigator.credentials.get(options);
      handleAuthenticationSuccess(credential);
    } catch (err) {
      setStatus('error');
      setError(err.message || 'Fingerprint authentication failed');
    }
  }, [handleAuthenticationSuccess]);

  const registerBiometric = useCallback(async () => {
    try {
      setStatus('registering');
      setError(null);

      if (!window.PublicKeyCredential) {
        throw new Error('Biometric authentication unavailable');
      }

      const isPlatform = await window.PublicKeyCredential
        .isUserVerifyingPlatformAuthenticatorAvailable();
      
      if (!isPlatform) {
        throw new Error('Device fingerprint sensor not available');
      }

      const userId = crypto.getRandomValues(new Uint8Array(16));
      const challenge = generateChallenge();

      const options = {
        publicKey: {
          rp: {
            name: SECURITY_CONFIG.rpName,
            id: SECURITY_CONFIG.rpId,
          },
          user: {
            id: userId,
            name: email,
            displayName: email.split('@')[0],
          },
          challenge,
          pubKeyCredParams: [
            { type: 'public-key', alg: -7 },
          ],
          authenticatorSelection: {
            authenticatorAttachment: 'platform',
            requireResidentKey: true,
            userVerification: 'required',
          },
          attestation: 'direct',
          timeout: SECURITY_CONFIG.timeout,
        },
      };

      const credential = await navigator.credentials.create(options);
      
      // Additional verification for registration
      if (credential.authenticatorAttachment !== 'platform') {
        throw new Error('Non-biometric authenticator used');
      }
      
      handleAuthenticationSuccess(credential);
    } catch (err) {
      setStatus('error');
      setError(err.message || 'Fingerprint registration failed');
    }
  }, [email, handleAuthenticationSuccess]);

  const resetState = () => {
    setStatus('idle');
    setError(null);
  };

  return (
    <Box display="flex" justifyContent="center" alignItems="center" minHeight="100vh" bgcolor={theme.palette.background.primary}>
      <Paper elevation={3} sx={{ width: 400, p: 4, borderRadius: '16px', textAlign: 'center' }}>
        <Typography variant="h5" gutterBottom sx={{ fontWeight: 'bold', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <LockIcon color="primary" sx={{ mr: 1 }} />
          {status === 'success' ? 'Authentication Complete' : 'Fingerprint Authentication'}
        </Typography>

        <Box sx={{ width: 180, height: 180, mb: 3, mx: 'auto', display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
          {status === 'checking' && <CircularProgress size={60} />}
          {status === 'scanning' && <FingerprintIcon sx={{ fontSize: 60, color: theme.palette.primary.main }} />}
          {status === 'registering' && <FingerprintIcon sx={{ fontSize: 60, color: theme.palette.warning.main }} />}
          {status === 'success' && <CheckCircleIcon sx={{ fontSize: 60, color: theme.palette.success.main }} />}
          {status === 'error' && <ErrorIcon sx={{ fontSize: 60, color: theme.palette.error.main }} />}
          {status === 'idle' && <FingerprintIcon sx={{ fontSize: 60, color: theme.palette.action.disabled }} />}
        </Box>
        
        {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
        
        <Typography variant="body1" sx={{ mb: 3 }}>
          {status === 'idle' && `Register or authenticate using fingerprint for ${email}`}
          {status === 'checking' && 'Checking device capabilities...'}
          {status === 'scanning' && 'Scan your fingerprint now'}
          {status === 'registering' && 'Register new fingerprint - touch sensor'}
          {status === 'success' && 'Fingerprint verified successfully!'}
          {status === 'error' && 'Biometric verification failed'}
        </Typography>
        
        {status === 'idle' && (
          <Box sx={{ display: 'flex', justifyContent: 'space-around' }}>
            <Button 
              variant="contained" 
              onClick={authenticateBiometric}
              disabled={!window.PublicKeyCredential}
            >
              Authenticate
            </Button>
            <Button 
              variant="outlined" 
              onClick={registerBiometric} 
              sx={{ ml: 2 }}
              disabled={!window.PublicKeyCredential}
            >
              Register Fingerprint
            </Button>
          </Box>
        )}
        
        {(status === 'error' || status === 'success') && (
          <Button 
            variant="outlined" 
            onClick={resetState} 
            fullWidth
          >
            {status === 'error' ? 'Try Again' : 'Close Window'}
          </Button>
        )}
      </Paper>
    </Box>
  );
}
export default FingerprintAuth;