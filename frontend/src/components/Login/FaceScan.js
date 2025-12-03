import React, { useRef, useState, useEffect } from 'react';
import Webcam from 'react-webcam';
import { Button, CircularProgress, Box, Typography, Paper, IconButton } from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import CameraAltIcon from '@mui/icons-material/CameraAlt';

const FaceScanLogin = () => {
  const webcamRef = useRef(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [webcamReady, setWebcamReady] = useState(false);
  const [isPopup] = useState(!!window.opener);

  const APP_ORIGIN = window.opener ? window.opener.location.origin : window.location.origin;

  // Check webcam availability
  useEffect(() => {
    const checkWebcam = async () => {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({ video: true });
        stream.getTracks().forEach(track => track.stop());
        setWebcamReady(true);
      } catch (err) {
        setError('Camera access required. Please ensure your camera is connected and permissions are granted.');
      }
    };
    checkWebcam();
  }, []);

  // Add this useEffect at the top of FaceScanLogin component
  useEffect(() => {
    // Hide navbar by class or ID
    const navbar = document.querySelector('.navbar'); // Adjust selector to match your navbar
    if (navbar) navbar.style.display = 'none';

    return () => {
      // Show navbar again when component unmounts
      if (navbar) navbar.style.display = 'block';
    };
  }, []);

  const capture = async () => {
    setLoading(true);
    try {
      if (!webcamRef.current) {
        throw new Error('Webcam not initialized');
      }
      const imageSrc = webcamRef.current.getScreenshot({ quality: 0.8 });
      if (!imageSrc) {
        throw new Error('Failed to capture image');
      }

      // Send image to parent window
      window.opener.postMessage({
        type: 'face_scan',
        status: 'success',
        image: imageSrc
      }, APP_ORIGIN);

      // Close the window after short delay
      setTimeout(() => window.close(), 500);
    } catch (err) {
      setError('Failed to capture image: ' + err.message);
      window.opener.postMessage({
        type: 'face_scan',
        status: 'error',
        message: err.message
      }, APP_ORIGIN);
    } finally {
      setLoading(false);
    }
  };

  // Fallback UI if not in popup
  if (!isPopup) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="100vh" bgcolor="#f5f7fa">
        <Paper elevation={3} sx={{ p: 4, maxWidth: 500, textAlign: 'center', borderRadius: 3 }}>
          <Typography variant="h5" gutterBottom color="error">
            Invalid Access
          </Typography>
          <Typography sx={{ mb: 3 }}>
            This page must be opened from the login page's face recognition option.
          </Typography>
          <Button
            variant="contained"
            color="secondary"
            onClick={() => window.close()}
            sx={{ px: 4, py: 1.5 }}
          >
            Close Window
          </Button>
        </Paper>
      </Box>
    );
  }

  return (
    <Box
      display="flex"
      justifyContent="center"
      alignItems="center"
      minHeight="100vh"
      bgcolor="#f0f4f8"
      p={2}
    >
      <Paper
        elevation={4}
        sx={{
          width: '100%',
          maxWidth: 500,
          borderRadius: 3,
          overflow: 'hidden',
          position: 'relative'
        }}
      >
        {/* Header */}
        <Box
          bgcolor="#1976d2"
          color="white"
          p={2}
          display="flex"
          justifyContent="space-between"
          alignItems="center"
        >
          <Typography variant="h6">Face Verification</Typography>
          <IconButton
            color="inherit"
            onClick={() => window.close()}
            size="small"
          >
            <CloseIcon />
          </IconButton>
        </Box>

        {/* Main Content */}
        <Box p={3}>
          <Typography
            variant="body2"
            textAlign="center"
            mb={2}
            sx={{
              backgroundColor: '#e3f2fd',
              p: 1.5,
              borderRadius: 1,
              color: '#1976d2'
            }}
          >
            <strong>Privacy note:</strong> We do not store your actual photo.
            Instead, we convert your facial features into a secure digital identifier.
          </Typography>

          {/* Webcam Container */}
          <Box
            sx={{
              position: 'relative',
              width: '100%',
              paddingTop: '100%',
              backgroundColor: '#000',
              borderRadius: 2,
              overflow: 'hidden',
              margin: '0 auto',
              border: '2px solid #e0e0e0'
            }}
          >
            {!webcamReady ? (
              <Box
                display="flex"
                justifyContent="center"
                alignItems="center"
                height="100%"
                position="absolute"
                top={0}
                left={0}
                right={0}
                bottom={0}
              >
                <CircularProgress color="primary" />
              </Box>
            ) : (
              <Webcam
                audio={false}
                ref={webcamRef}
                screenshotFormat="image/jpeg"
                forceScreenshotSourceSize
                videoConstraints={{
                  facingMode: 'user',
                  width: { ideal: 640 },
                  height: { ideal: 640 }
                }}
                onUserMediaError={(err) => {
                  setError('Failed to access camera. Please check permissions.');
                  setWebcamReady(false);
                }}
                style={{
                  position: 'absolute',
                  top: '50%',
                  left: '50%',
                  transform: 'translate(-50%, -50%)',
                  width: '100%',
                  height: '100%',
                  objectFit: 'cover'
                }}
              />
            )}
          </Box>

          {/* Status Messages */}
          {error && (
            <Typography
              color="error"
              textAlign="center"
              mt={2}
              variant="body2"
            >
              {error}
            </Typography>
          )}

          {/* Capture Button */}
          <Button
            fullWidth
            variant="contained"
            color="primary"
            onClick={capture}
            disabled={loading || !webcamReady}
            sx={{
              mt: 3,
              py: 1.5,
              fontSize: '1rem',
              fontWeight: 600
            }}
            startIcon={!loading && <CameraAltIcon />}
          >
            {loading ? (
              <CircularProgress size={24} sx={{ color: 'white' }} />
            ) : (
              'Capture Image'
            )}
          </Button>

          <Typography
            variant="body2"
            textAlign="center"
            mt={1.5}
            color="textSecondary"
          >
            Position your face within the frame and ensure good lighting
          </Typography>
        </Box>
      </Paper>
    </Box>
  );
};

export default FaceScanLogin;