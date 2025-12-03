import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { getSessionWithExpiry, clearSession, setSessionWithExpiry } from '../../utils/sessionManager';
import FingerprintJS from '@fingerprintjs/fingerprintjs';
import {
  Container,
  Typography,
  Card,
  CardContent,
  List,
  ListItem,
  ListItemText,
  Divider,
  Button,
  Grid,
  Paper,
  Box,
  Chip,
  Avatar,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  CircularProgress,
  Snackbar,
  Alert,
  LinearProgress,
  IconButton
} from '@mui/material';
import {
  Fingerprint as FingerprintIcon,
  Face as FaceIcon,
  Email as EmailIcon,
  CalendarToday as CalendarIcon,
  ExitToApp as LogoutIcon,
  Add as AddIcon,
  CheckCircle as CheckCircleIcon,
  History as HistoryIcon,
  Lock as LockIcon,
  Security as SecurityIcon
} from '@mui/icons-material';
import { styled } from '@mui/material/styles';
import CryptoJS from 'crypto-js';
import LockOpenIcon from '@mui/icons-material/LockOpen';
import UpdateIcon from '@mui/icons-material/Update';
import UserNav from '../NavBar/UserNav';

// Custom styled components
const DiagonalCard = styled(Card)(({ theme }) => ({
  marginBottom: theme.spacing(3),
  borderRadius: '16px',
  boxShadow: '0 8px 32px rgba(0,0,0,0.1)',
  overflow: 'hidden',
  position: 'relative',
  backgroundColor: '#f9fbfd',
}));

const DiagonalSeparator = styled('div')(({ theme }) => ({
  position: 'absolute',
  top: 0,
  right: 0,
  width: '100%',
  height: '100%',
  overflow: 'hidden',
  zIndex: 1,
  [theme.breakpoints.down('md')]: {
    display: 'none'
  },
  '&:before': {
    content: '""',
    position: 'absolute',
    top: 0,
    right: 0,
    width: '200%',
    height: '200%',
    background: 'linear-gradient(45deg, transparent 50%, white 50%)',
    transform: 'translateX(50%) rotate(-20deg)',
    transformOrigin: 'top right',
    zIndex: 2,
  },
  '&:after': {
    content: '""',
    position: 'absolute',
    top: 0,
    right: 0,
    width: '200%',
    height: '200%',
    background: 'linear-gradient(45deg, transparent 49.8%, rgba(25, 118, 210, 0.1) 49.8%, rgba(25, 118, 210, 0.1) 50.2%, white 50.2%)',
    transform: 'translateX(50%) rotate(-20deg)',
    transformOrigin: 'top right',
    zIndex: 1,
  }
}));

const UserInfoSection = styled(Grid)(({ theme }) => ({
  position: 'relative',
  padding: theme.spacing(4),
  backgroundColor: 'rgba(25, 118, 210, 0.03)',
  zIndex: 3,
}));

const AuthSection = styled(Grid)(({ theme }) => ({
  position: 'relative',
  padding: theme.spacing(4),
  zIndex: 3,
}));

const MethodChip = styled(Chip)(({ theme }) => ({
  marginRight: theme.spacing(1),
  marginBottom: theme.spacing(1),
  padding: theme.spacing(0.5),
  fontSize: '0.9rem',
  backgroundColor: theme.palette.grey[100],
  border: `1px solid ${theme.palette.divider}`,
  fontWeight: 500,
}));

const AddMethodCard = styled(Paper)(({ theme }) => ({
  padding: theme.spacing(2),
  borderRadius: '12px',
  transition: 'all 0.3s ease',
  background: 'linear-gradient(135deg, #f5f9ff 0%, #eef5ff 100%)',
  border: '1px solid rgba(25, 118, 210, 0.1)',
  '&:hover': {
    transform: 'translateY(-5px)',
    boxShadow: '0 6px 20px rgba(25, 118, 210, 0.15)',
    borderColor: 'rgba(25, 118, 210, 0.3)',
  },
}));

const DocumentID = styled('div')(({ theme }) => ({
  background: 'linear-gradient(120deg, rgba(25, 118, 210, 0.1), rgba(25, 118, 210, 0.05))',
  padding: theme.spacing(1.5),
  borderRadius: '8px',
  borderLeft: '3px solid #1976d2',
  fontFamily: 'monospace',
  fontWeight: 600,
  fontSize: '0.9rem',
  marginTop: theme.spacing(1),
}));

// Helper function to normalize signup_method
const normalizeSignupMethod = (method) => {
  if (Array.isArray(method)) return method;
  if (typeof method === 'string') {
    if (method === 'both') return ['face', 'fingerprint'];
    if (method === 'none') return [];
    return [method];
  }
  return [];
};

const UserProfile = () => {
  const ENCRYPTION_KEY = process.env.REACT_APP_ENCRYPTION_KEY || 'EVOd/1ytp2RnK9SSzfm6qYfY/FqtUopSi3+K/SeAAnk=';
  const navigate = useNavigate();
  const [userData, setUserData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [openAddMethodDialog, setOpenAddMethodDialog] = useState(false);
  const [selectedMethod, setSelectedMethod] = useState('');
  const [addingMethod, setAddingMethod] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [freezingMethod, setFreezingMethod] = useState(null);
  const [snackbar, setSnackbar] = useState({
    open: false,
    message: '',
    severity: 'success'
  });

  // Email is always present, so we don't need to show it in available methods
  const availableMethods = [
    { id: 'fingerprint', name: 'Fingerprint', icon: <FingerprintIcon /> },
    { id: 'face', name: 'Facial Recognition', icon: <FaceIcon /> }
  ];

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

  // SHA-256 hashing function
  const sha256 = async (str) => {
    const buffer = new TextEncoder().encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  };

  // Get device ID
  const getDeviceID = async () => {
    const fp = await FingerprintJS.load();
    const result = await fp.get();
    const visitorId = result.visitorId;
    return sha256(visitorId);
  };

  const handleToggleFreeze = async (method) => {
    setFreezingMethod(method);
    try {
      const deviceId = await getDeviceID();
      const payload = {
        email: userData.email,
        method,
        deviceId
      };

      const encryptedData = encryptData(payload);
      const response = await axios.post('http://localhost:5000/api/toggle-method-freeze', {
        encryptedData
      });

      if (response.data.success) {
        // Refetch user data to update UI
        const fetchResponse = await axios.post('http://localhost:5000/api/user-data', {
          encryptedSession: encryptData(getSessionWithExpiry('secureSession'))
        });

        if (fetchResponse.data.success) {
          setUserData({
            ...fetchResponse.data.data,
            signup_method: normalizeSignupMethod(fetchResponse.data.data.signup_method).concat(fetchResponse.data.data.frozen_methods)
          });
        }

        setSnackbar({
          open: true,
          message: response.data.message || `Successfully ${userData.frozen_methods?.includes(method) ? 'unfrozen' : 'frozen'} ${method} authentication`,
          severity: 'success'
        });
      } else {
        throw new Error(response.data.message || 'Toggle freeze failed');
      }
    } catch (err) {
      setSnackbar({
        open: true,
        message: `Error: ${err.message}`,
        severity: 'error'
      });
    } finally {
      setFreezingMethod(null);
    }
  };

  useEffect(() => {
    const fetchUserData = async () => {
      try {
        setLoading(true);
        const Session = getSessionWithExpiry('secureSession');

        if (!Session) {
          clearSession('secureSession');
          navigate('/signup');
          return;
        }

        const response = await axios.post('http://localhost:5000/api/user-data', {
          encryptedSession: encryptData(Session)
        });

        if (!response.data.success) {
          if (response.data.message === 'No valid session' ||
            response.data.message === 'Session invalid due to logout') {
            clearSession('secureSession');
            navigate('/signup');
            return;
          }
          throw new Error(response.data.message);
        }

        // Normalize signup_method to array format (DO NOT add email here)
        const normalizedData = {
          ...response.data.data,
          signup_method: normalizeSignupMethod(response.data.data.signup_method).concat(response.data.data.frozen_methods)
        };

        setUserData(normalizedData);
      } catch (err) {
        console.error('Error fetching user data:', err);
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchUserData();
  }, [navigate, encryptData]);

  const handleLogout = () => {
    clearSession('secureSession');
    navigate('/signup');
  };

  const handleAddMethodClick = (method) => {
    setSelectedMethod(method);
    setOpenAddMethodDialog(true);
  };

  const openScannerWindow = async (method) => {
    setScanning(true);
    const url = method === 'face' ? '/facescan' : '/fingerprint';
    const width = 375;
    const height = 667;
    const left = (window.screen.width - width) / 2;
    const top = (window.screen.height - height) / 2;

    const scanUrl = `${url}?email=${encodeURIComponent(userData.email)}`;

    const newWindow = window.open(
      scanUrl,
      '_blank',
      `width=${width},height=${height},left=${left},top=${top}`
    );

    const messageHandler = async (event) => {
      if (event.source === newWindow) {
        const data = event.data;
        if (data.type === 'fingerprint_result' || data.type === 'face_scan') {
          try {
            if (data.status === 'success' || data.data) {
              const deviceId = await getDeviceID();
              const updatePayload = {
                email: userData.email,
                deviceId,
                method: selectedMethod,
                data: data.type === 'fingerprint_result' ? {
                  publicKey: data.publicKey.id,
                  biometricData: data.biometricData
                } : {
                  faceData: data.data
                }
              };

              // Encrypt the update payload
              const encryptedUpdate = encryptData(updatePayload);

              // Send update to backend
              const response = await axios.post('http://localhost:5000/api/update-user', {
                encryptedUpdate
              });

              if (response.data.success) {
                // Update UI with new method
                setUserData(prev => {
                  const currentMethods = normalizeSignupMethod(prev.signup_method);
                  const updatedMethods = [...new Set([...currentMethods, selectedMethod])];
                  return {
                    ...prev,
                    signup_method: updatedMethods
                  };
                });

                setSnackbar({
                  open: true,
                  message: `${selectedMethod === 'face' ? 'Facial Recognition' : 'Fingerprint'} added successfully!`,
                  severity: 'success'
                });
              } else {
                throw new Error(response.data.message || 'Update failed');
              }
            } else {
              throw new Error(data.error || 'Scan failed');
            }
          } catch (err) {
            setSnackbar({
              open: true,
              message: `Failed to add method: ${err.message}`,
              severity: 'error'
            });
          } finally {
            setScanning(false);
            setAddingMethod(false);
            newWindow.close();
            window.removeEventListener('message', messageHandler);
          }
        }
      }
    };

    window.addEventListener('message', messageHandler);
  };

  const handleAddMethod = async () => {
    setAddingMethod(true);
    setOpenAddMethodDialog(false);
    await openScannerWindow(selectedMethod);
  };

  const handleCloseSnackbar = () => {
    setSnackbar(prev => ({ ...prev, open: false }));
  };

  if (loading) {
    return (
      <Container maxWidth="md" sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
        <CircularProgress size={60} />
      </Container>
    );
  }

  if (error) {
    return (
      <Container maxWidth="md" sx={{ py: 4 }}>
        <Alert severity="error">{error}</Alert>
      </Container>
    );
  }

  if (!userData) return null;

  // Extract document ID (last 6 characters of _id)
  const documentId = userData._id ? `CHAIN-${userData._id.slice(-6).toUpperCase()}` : 'CHAIN-XXXXXX';

  // Define all possible methods
  const allMethods = [
    { id: 'email', name: 'Email', icon: <EmailIcon /> },
    ...availableMethods
  ];

  const getMethodInfo = (methodId) => {
    return allMethods.find(m => m.id === methodId) || { id: methodId, name: methodId, icon: <LockIcon /> };
  };

  // Get all biometric methods in use (active and frozen)
  const biometricMethodsInUse = userData.signup_method || [];
  const frozenMethodsList = userData.frozen_methods || [];

  // All methods in use (email + biometric)
  const methodsInUse = ['email', ...biometricMethodsInUse];

  // Prepare active methods with frozen status
  const activeMethods = methodsInUse.map(id => {
    const methodInfo = getMethodInfo(id);
    const isFrozen = frozenMethodsList.includes(id);
    return { ...methodInfo, isFrozen };
  });

  // Available methods to add (not in use)
  const availableMethodsToAdd = availableMethods.filter(m => !biometricMethodsInUse.includes(m.id));

  return (
    <Container maxWidth="lg" className='mt-5' sx={{ py: 4 }}>
      <Box style={{ width:"60px"}}>
        <UserNav />
      </Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 4 }}>
        <Typography variant="h4" component="h1" sx={{ fontWeight: 700, color: 'primary.main', display: "none" }}>
          <SecurityIcon sx={{ verticalAlign: 'middle', mr: 1.5, fontSize: '2rem' }} />
          CHAIN ID
        </Typography>
        <Box sx={{ display: 'none' }}>
          <Button
            variant="contained"
            color="error"
            startIcon={<LogoutIcon />}
            onClick={handleLogout}
            sx={{ borderRadius: '10px', px: 3, py: 1 }}
          >
            Logout
          </Button>
        </Box>
      </Box>

      {/* Combined User Info and Authentication Card with Diagonal Separator */}
      <DiagonalCard>
        <DiagonalSeparator />
        <CardContent sx={{ p: 0 }}>
          <Grid container>
            {/* Left Section: User Information */}
            <UserInfoSection item xs={12} md={6}>
              <Box sx={{ mb: 3 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: 'text.secondary' }}>
                  Account Information
                </Typography>
                <Typography variant="h5" sx={{ fontWeight: 700, mb: 1.5 }}>
                  {userData.email}
                </Typography>

                <DocumentID>
                  {documentId}
                </DocumentID>
              </Box>

              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <Box sx={{
                    display: 'flex',
                    alignItems: 'center',
                    p: 2,
                    borderRadius: '8px',
                    backgroundColor: 'rgba(255, 255, 255, 0.7)',
                    border: '1px solid rgba(0, 0, 0, 0.05)',
                    mb: 2
                  }}>
                    <EmailIcon color="primary" sx={{ mr: 2, fontSize: '1.8rem' }} />
                    <Box>
                      <Typography variant="body2" color="text.secondary">
                        Email Address
                      </Typography>
                      <Typography variant="body1" sx={{ fontWeight: 600 }}>
                        {userData.email}
                      </Typography>
                    </Box>
                  </Box>
                </Grid>

                <Grid item xs={12} sm={6}>
                  <Box sx={{
                    display: 'flex',
                    alignItems: 'center',
                    p: 2,
                    borderRadius: '8px',
                    backgroundColor: 'rgba(255, 255, 255, 0.7)',
                    border: '1px solid rgba(0, 0, 0, 0.05)',
                    height: '100%'
                  }}>
                    <CalendarIcon color="primary" sx={{ mr: 2, fontSize: '1.8rem' }} />
                    <Box>
                      <Typography variant="body2" color="text.secondary">
                        Account Created
                      </Typography>
                      <Typography variant="body1" sx={{ fontWeight: 600 }}>
                        {new Date(userData.created_at).toLocaleDateString('en-US', {
                          year: 'numeric',
                          month: 'long',
                          day: 'numeric'
                        })}
                      </Typography>
                    </Box>
                  </Box>
                </Grid>

                <Grid item xs={12} sm={6}>
                  <Box sx={{
                    display: 'flex',
                    alignItems: 'center',
                    p: 2,
                    borderRadius: '8px',
                    backgroundColor: 'rgba(255, 255, 255, 0.7)',
                    border: '1px solid rgba(0, 0, 0, 0.05)',
                    height: '100%'
                  }}>
                    <LockIcon color="primary" sx={{ mr: 2, fontSize: '1.8rem' }} />
                    <Box>
                      <Typography variant="body2" color="text.secondary">
                        Security Status
                      </Typography>
                      <Typography variant="body1" color="success.main" sx={{ fontWeight: 600 }}>
                        <CheckCircleIcon sx={{
                          fontSize: '1rem',
                          verticalAlign: 'middle',
                          mr: 0.5
                        }} />
                        Account Protected
                      </Typography>
                    </Box>
                  </Box>
                </Grid>
                <Grid item xs={12} sm={6}>
                  <Box sx={{
                    display: 'flex',
                    alignItems: 'center',
                    p: 2,
                    borderRadius: '8px',
                    backgroundColor: 'rgba(255, 255, 255, 0.7)',
                    border: '1px solid rgba(0, 0, 0, 0.05)',
                    height: '100%'
                  }}>
                    <UpdateIcon color="primary" sx={{ mr: 2, fontSize: '1.8rem' }} />
                    <Box>
                      <Typography variant="body2" color="text.secondary">
                        Last Updated
                      </Typography>
                      <Typography variant="body1" sx={{ fontWeight: 600 }}>
                        {userData.updated_at ?
                          new Date(userData.updated_at).toLocaleDateString('en-US', {
                            year: 'numeric',
                            month: 'long',
                            day: 'numeric'
                          })
                          : 'Never'}
                      </Typography>
                    </Box>
                  </Box>
                </Grid>
              </Grid>
            </UserInfoSection>

            {/* Right Section: Authentication Methods */}
            <AuthSection item xs={12} md={6}>
              <Box sx={{ mb: availableMethodsToAdd.length > 0 ? 3 : 0 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 1.5 }}>
                  Authentication Methods
                </Typography>

                <Grid container spacing={2}>
                  {activeMethods.map(method => {
                    const isEmail = method.id === 'email';
                    const isFrozen = method.isFrozen;

                    return (
                      <Grid item xs={12} key={method.id}>
                        <Paper elevation={0} sx={{
                          p: 2,
                          borderRadius: '12px',
                          border: '1px solid',
                          borderColor: isFrozen ? 'error.light' : 'rgba(0, 0, 0, 0.05)',
                          backgroundColor: isFrozen ? 'rgba(255, 0, 0, 0.03)' : 'rgba(255, 255, 255, 0.7)'
                        }}>
                          <Box sx={{ display: 'flex', alignItems: 'center' }}>
                            <Avatar sx={{
                              bgcolor: isFrozen ? 'rgba(244, 67, 54, 0.1)' : 'rgba(25, 118, 210, 0.1)',
                              color: isFrozen ? 'error.main' : 'primary.main',
                              mr: 2,
                              width: 56,
                              height: 56
                            }}>
                              {method.icon}
                            </Avatar>
                            <Box sx={{ flexGrow: 1 }}>
                              <Typography variant="h6" sx={{ fontWeight: 700, color: isFrozen ? 'error.main' : 'inherit' }}>
                                {method.name}
                                {isFrozen && (
                                  <Chip
                                    label="Frozen"
                                    size="small"
                                    color="error"
                                    sx={{ ml: 1, fontSize: '0.7rem', height: '20px' }}
                                  />
                                )}
                              </Typography>
                              <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                                {method.id === 'email'
                                  ? 'Email-based authentication'
                                  : method.id === 'face'
                                    ? 'Facial recognition login'
                                    : 'Fingerprint authentication'}
                              </Typography>
                            </Box>
                            {!isEmail && (
                              <Button
                                size="medium"
                                variant={isFrozen ? "contained" : "outlined"}
                                color={isFrozen ? "success" : "error"}
                                startIcon={isFrozen ? <LockOpenIcon /> : <LockIcon />}
                                onClick={() => handleToggleFreeze(method.id)}
                                disabled={freezingMethod === method.id}
                                sx={{
                                  borderRadius: '8px',
                                  fontWeight: 600,
                                  minWidth: '120px'
                                }}
                              >
                                {freezingMethod === method.id
                                  ? <CircularProgress size={20} />
                                  : isFrozen ? 'Unfreeze' : 'Freeze'}
                              </Button>
                            )}
                          </Box>
                        </Paper>
                      </Grid>
                    );
                  })}
                </Grid>
              </Box>

              {/* Add Additional Methods Section */}
              {availableMethodsToAdd.length > 0 && (
                <Box>
                  <Typography variant="body1" sx={{ fontWeight: 600, mb: 2, color: 'text.secondary' }}>
                    Enhance Security with Additional Methods:
                  </Typography>

                  <Grid container spacing={2}>
                    {availableMethodsToAdd.map(method => (
                      <Grid item xs={12} key={method.id}>
                        <AddMethodCard elevation={0}>
                          <Box sx={{ display: 'flex', alignItems: 'center' }}>
                            <Avatar sx={{
                              bgcolor: 'rgba(25, 118, 210, 0.1)',
                              color: 'primary.main',
                              mr: 2,
                              width: 56,
                              height: 56
                            }}>
                              {method.icon}
                            </Avatar>
                            <Box sx={{ flexGrow: 1 }}>
                              <Typography variant="h6" sx={{ fontWeight: 700 }}>
                                {method.name}
                              </Typography>
                              <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                                {method.id === 'face'
                                  ? 'Facial recognition login'
                                  : 'Fingerprint authentication'}
                              </Typography>
                            </Box>
                            <Box>
                              {scanning && selectedMethod === method.id ? (
                                <CircularProgress size={24} />
                              ) : (
                                <Button
                                  size="medium"
                                  variant="contained"
                                  startIcon={<AddIcon />}
                                  onClick={() => handleAddMethodClick(method.id)}
                                  sx={{
                                    borderRadius: '8px',
                                    boxShadow: '0 2px 8px rgba(25, 118, 210, 0.2)',
                                    '&:hover': {
                                      boxShadow: '0 4px 12px rgba(25, 118, 210, 0.3)',
                                    }
                                  }}
                                >
                                  ADD
                                </Button>
                              )}
                            </Box>
                          </Box>
                        </AddMethodCard>
                      </Grid>
                    ))}
                  </Grid>

                  <Typography variant="body2" sx={{ mt: 2, color: 'text.secondary', fontStyle: 'italic' }}>
                    <LockIcon sx={{ fontSize: '1rem', verticalAlign: 'middle', mr: 0.5 }} />
                    Adding multiple authentication methods enhances your account security.
                  </Typography>
                </Box>
              )}
            </AuthSection>
          </Grid>
        </CardContent>
      </DiagonalCard>

      {/* Login History Card */}
      <DiagonalCard>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              <HistoryIcon color="primary" sx={{ mr: 1.5, fontSize: '2rem' }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Login History
              </Typography>
            </Box>
            <Button
              variant="outlined"
              color="secondary"
              startIcon={<LogoutIcon />}
              onClick={handleLogout}
              sx={{ borderRadius: '8px' }}
            >
              Sign Out
            </Button>
          </Box>

          <Divider sx={{ mb: 3, borderColor: 'rgba(0, 0, 0, 0.08)' }} />

          {userData.login_history?.length > 0 ? (
            <List sx={{
              maxHeight: '400px',
              overflow: 'auto',
              borderRadius: '12px',
              border: '1px solid rgba(0, 0, 0, 0.08)',
              boxShadow: 'inset 0 2px 8px rgba(0,0,0,0.05)'
            }}>
              {userData.login_history.map((login, index) => (
                <React.Fragment key={index}>
                  <ListItem sx={{ py: 2 }}>
                    <ListItemText
                      primary={new Date(login.timestamp).toLocaleString('en-US', {
                        dateStyle: 'medium',
                        timeStyle: 'short'
                      })}
                      primaryTypographyProps={{ fontWeight: 600, color: 'text.primary' }}
                      secondary={
                        <>
                          <Box component="span" display="block" sx={{ mt: 1 }}>
                            <Typography component="span" variant="body2" color="text.secondary">
                              Device:
                            </Typography>
                            <Chip
                              label={`${login.device_id?.substring(0, 8)}...${login.device_id?.substring(56)}`}
                              size="small"
                              sx={{
                                ml: 1,
                                fontFamily: 'monospace',
                                backgroundColor: 'rgba(0, 0, 0, 0.05)',
                                color: 'text.primary',
                                fontWeight: 500
                              }}
                            />
                          </Box>
                          <Box component="span" display="block" sx={{ mt: 1 }}>
                            <Typography component="span" variant="body2" color="text.secondary">
                              Method:
                            </Typography>
                            <Chip
                              label={login.method}
                              size="small"
                              sx={{
                                ml: 1,
                                textTransform: 'capitalize',
                                fontWeight: 500,
                                backgroundColor: login.method === 'email'
                                  ? 'rgba(25, 118, 210, 0.1)'
                                  : login.method === 'face'
                                    ? 'rgba(76, 175, 80, 0.1)'
                                    : 'rgba(156, 39, 176, 0.1)',
                                color: login.method === 'email'
                                  ? 'primary.main'
                                  : login.method === 'face'
                                    ? 'success.main'
                                    : 'secondary.main'
                              }}
                              icon={
                                login.method === 'email' ? <EmailIcon fontSize="small" /> :
                                  login.method === 'face' ? <FaceIcon fontSize="small" /> :
                                    <FingerprintIcon fontSize="small" />
                              }
                            />
                          </Box>
                        </>
                      }
                    />
                  </ListItem>
                  {index < userData.login_history.length - 1 && (
                    <Divider sx={{ mx: 2, borderColor: 'rgba(0, 0, 0, 0.05)' }} />
                  )}
                </React.Fragment>
              ))}
            </List>
          ) : (
            <Box sx={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              py: 6,
              border: '1px dashed rgba(0, 0, 0, 0.12)',
              borderRadius: '12px',
              backgroundColor: 'rgba(0, 0, 0, 0.02)'
            }}>
              <HistoryIcon sx={{ fontSize: 60, color: 'rgba(0, 0, 0, 0.12)', mb: 2 }} />
              <Typography variant="body1" color="textSecondary">
                No login history available yet
              </Typography>
            </Box>
          )}
        </CardContent>
      </DiagonalCard>

      {/* Add Method Dialog */}
      <Dialog
        open={openAddMethodDialog}
        onClose={() => setOpenAddMethodDialog(false)}
        PaperProps={{
          sx: {
            borderRadius: '16px',
            width: '100%',
            maxWidth: '500px',
            overflow: 'hidden'
          }
        }}
      >
        <DialogTitle sx={{
          fontWeight: 700,
          fontSize: '1.5rem',
          display: 'flex',
          alignItems: 'center',
          backgroundColor: 'primary.main',
          color: 'white',
          py: 2
        }}>
          {availableMethods.find(m => m.id === selectedMethod)?.icon}
          <Box sx={{ ml: 1.5 }}>
            Add {availableMethods.find(m => m.id === selectedMethod)?.name || 'Method'}
          </Box>
        </DialogTitle>
        <DialogContent sx={{ py: 3 }}>
          <Box sx={{ textAlign: 'center', mb: 3 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 1 }}>
              Secure Setup Process
            </Typography>
            <Typography variant="body1" color="text.secondary">
              Follow these steps to add biometric security
            </Typography>
          </Box>

          <Box sx={{
            display: 'flex',
            justifyContent: 'center',
            mb: 3,
            position: 'relative'
          }}>
            <Box sx={{
              width: 120,
              height: 120,
              borderRadius: '50%',
              backgroundColor: 'rgba(25, 118, 210, 0.1)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              border: '2px solid rgba(25, 118, 210, 0.3)'
            }}>
              {availableMethods.find(m => m.id === selectedMethod)?.icon ||
                <AddIcon sx={{ fontSize: '3rem', color: 'primary.main' }} />
              }
            </Box>
          </Box>

          <Box component="div" sx={{
            backgroundColor: 'rgba(25, 118, 210, 0.03)',
            borderRadius: '12px',
            p: 2,
            mb: 2,
            borderLeft: '3px solid #1976d2'
          }}>
            <ol style={{ paddingLeft: '20px', margin: 0 }}>
              <li style={{ marginBottom: '12px' }}>
                <Typography sx={{ fontWeight: 500 }}>
                  Position your {selectedMethod === 'face' ? 'face' : 'finger'} -
                  Ensure proper lighting and positioning
                </Typography>
              </li>
              <li style={{ marginBottom: '12px' }}>
                <Typography sx={{ fontWeight: 500 }}>
                  Follow on-screen instructions -
                  Complete the scanning process in the new window
                </Typography>
              </li>
              <li>
                <Typography sx={{ fontWeight: 500 }}>
                  Verification -
                  System will securely encrypt and store your biometric data
                </Typography>
              </li>
            </ol>
          </Box>

          <Box sx={{
            backgroundColor: 'rgba(255, 229, 100, 0.2)',
            borderRadius: '8px',
            p: 2,
            mt: 2,
            borderLeft: '4px solid #ffc107'
          }}>
            <Typography variant="body2" sx={{ display: 'flex' }}>
              <LockIcon sx={{ color: '#ffc107', mr: 1, mt: 0.2 }} />
              <span>
                Your biometric data is <strong>encrypted</strong> and never stored in raw format.
                We use military-grade encryption to protect your information.
              </span>
            </Typography>
          </Box>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 3, pt: 0 }}>
          <Button
            onClick={() => setOpenAddMethodDialog(false)}
            disabled={addingMethod}
            variant="outlined"
            sx={{
              borderRadius: '8px',
              px: 2.5,
              borderWidth: '2px',
              fontWeight: 600,
              '&:hover': { borderWidth: '2px' }
            }}
          >
            Cancel
          </Button>
          <Button
            onClick={handleAddMethod}
            color="primary"
            variant="contained"
            disabled={addingMethod}
            startIcon={addingMethod ? <CircularProgress size={20} /> : null}
            sx={{
              borderRadius: '8px',
              px: 3,
              fontWeight: 600,
              boxShadow: '0 4px 12px rgba(25, 118, 210, 0.3)',
              '&:hover': {
                boxShadow: '0 6px 16px rgba(25, 118, 210, 0.4)',
              }
            }}
          >
            {addingMethod ? 'Initializing...' : 'Begin Setup'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Scanning Progress */}
      {scanning && (
        <Box sx={{
          position: 'fixed',
          top: 0,
          left: 0,
          width: '100%',
          height: '100%',
          backgroundColor: 'rgba(255, 255, 255, 0.95)',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
          alignItems: 'center',
          zIndex: 1300
        }}>
          <Box sx={{
            width: 120,
            height: 120,
            borderRadius: '50%',
            backgroundColor: 'rgba(25, 118, 210, 0.1)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            mb: 3,
            border: '2px solid rgba(25, 118, 210, 0.3)'
          }}>
            {selectedMethod === 'face' ?
              <FaceIcon sx={{ fontSize: '3rem', color: 'primary.main' }} /> :
              <FingerprintIcon sx={{ fontSize: '3rem', color: 'primary.main' }} />
            }
          </Box>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 1 }}>
            {selectedMethod === 'face' ? 'Facial Scanning' : 'Fingerprint Scanning'}
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Please complete the process in the new window
          </Typography>
          <LinearProgress
            sx={{
              height: 8,
              width: '40%',
              borderRadius: 4,
              backgroundColor: 'rgba(25, 118, 210, 0.1)',
              '& .MuiLinearProgress-bar': {
                borderRadius: 4,
                backgroundColor: 'primary.main'
              }
            }}
          />
          <Button
            variant="outlined"
            color="primary"
            sx={{ mt: 3, borderRadius: '8px', fontWeight: 600 }}
            onClick={() => setScanning(false)}
          >
            Cancel Scan
          </Button>
        </Box>
      )}

      {/* Snackbar for notifications */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={handleCloseSnackbar}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert
          onClose={handleCloseSnackbar}
          severity={snackbar.severity}
          sx={{
            width: '100%',
            borderRadius: '12px',
            boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
            alignItems: 'center',
            fontWeight: 500
          }}
          iconMapping={{
            success: <CheckCircleIcon fontSize="inherit" />,
            error: <SecurityIcon fontSize="inherit" />
          }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Container>
  );
};

export default UserProfile;