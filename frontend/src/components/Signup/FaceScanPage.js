import { useEffect, useRef, useState, useCallback } from "react";
import { Button, Typography, Alert, CircularProgress, Box, Container } from "@mui/material";
import { CameraAlt as CameraIcon, CheckCircle as CheckCircleIcon, HourglassEmpty as HourglassIcon } from "@mui/icons-material";
import './FaceScan.css';
import axios from "axios";

const FaceScan = () => {
    const videoRef = useRef(null);
    const canvasRef = useRef(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [scanned, setScanned] = useState(false);
    const [cameraActive, setCameraActive] = useState(true);
    const [processing, setProcessing] = useState(false); // New state for processing

    const urlParams = new URLSearchParams(window.location.search);
    const email = urlParams.get('email') || 'user@secureapp.com';

    const captureFaceData = useCallback(async () => {
        const canvas = canvasRef.current;
        const video = videoRef.current;
        if (canvas && video) {
            const ctx = canvas.getContext("2d");
            canvas.width = video.videoWidth * 2;
            canvas.height = video.videoHeight * 2;
            ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
            const imageData = canvas.toDataURL("image/jpeg");
            
            const byteString = atob(imageData.split(',')[1]);
            const arrayBuffer = new ArrayBuffer(byteString.length);
            const uint8Array = new Uint8Array(arrayBuffer);
            for (let i = 0; i < byteString.length; i++) {
                uint8Array[i] = byteString.charCodeAt(i);
            }
            const blob = new Blob([uint8Array], { type: 'image/jpeg' });
    
            // Stop camera immediately after capture
            if (videoRef.current && videoRef.current.srcObject) {
                videoRef.current.srcObject.getTracks().forEach(track => track.stop());
                setCameraActive(false);
            }
            
            // Show processing state
            setProcessing(true);
            sendDataToSignup(blob);
        }
    }, []);

    const startCamera = useCallback(async () => {
        try {
            const stream = await navigator.mediaDevices.getUserMedia({
                video: {
                    facingMode: 'user',
                    width: { ideal: 1280 },
                    height: { ideal: 720 }
                }
            });
            if (videoRef.current) {
                videoRef.current.srcObject = stream;
                videoRef.current.onloadedmetadata = () => {
                    videoRef.current.play();
                    setLoading(false);
                    setCameraActive(true);
                };
            }
        } catch (error) {
            setError("Error accessing camera. Please check permissions and try again.");
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        startCamera();
        return () => {
            if (videoRef.current && videoRef.current.srcObject) {
                videoRef.current.srcObject.getTracks().forEach(track => track.stop());
            }
        };
    }, [startCamera]);

    const sendDataToSignup = async (imageBlob) => {
        try {
            const formData = new FormData();
            formData.append('image', imageBlob);
            formData.append('email', email);
            
            const response = await axios.post('http://localhost:5000/upload', formData, {
              headers: {
                'Content-Type': 'multipart/form-data'
              }
            });
            
            setProcessing(false); // Hide processing indicator
            setScanned(true);
            
            if (window.opener) {
                window.opener.postMessage({ type: "face_scan", data: response.data.faceData }, "*");
                setTimeout(() => window.close(), 1500);
            }
        } catch (error) {
            setProcessing(false); // Hide processing indicator on error
            
            // Restart camera on error
            setCameraActive(true);
            startCamera();
            
            if (error.response) {
                alert(error.response.data.error || 'Error uploading image');
            } else if (error.request) {
                alert('No response from server. Check your network or server status.');
            } else {
                alert('An unexpected error occurred.');
            }
        }
    };

    const restartCamera = () => {
        setLoading(true);
        setError(null);
        setScanned(false);
        startCamera();
    };

    return (
        <Container maxWidth="sm" className="face-scan-container">
            <Box textAlign="center" mb={4}>
                <CameraIcon color="primary" sx={{ fontSize: 60 }} />
                <Typography variant="h4" gutterBottom sx={{ fontWeight: 600, mt: 2 }}>
                    Face Verification
                </Typography>
                <Typography variant="body1" color="text.secondary">
                    {processing 
                        ? "Processing your face recognition..."
                        : scanned
                            ? "Verification successful!"
                            : loading
                                ? "Initializing camera..."
                                : error
                                    ? "Verification failed"
                                    : "Align your face within the frame"}
                </Typography>
            </Box>

            <Box
                sx={{
                    position: 'relative',
                    borderRadius: '12px',
                    overflow: 'hidden',
                    boxShadow: 3,
                    mb: 4,
                    border: '1px solid',
                    borderColor: 'divider',
                    minHeight: '300px',
                    backgroundColor: 'background.default'
                }}
            >
                {/* Show video feed only when camera is active */}
                {cameraActive && !scanned && !error && !processing && (
                    <video
                        ref={videoRef}
                        autoPlay
                        playsInline
                        muted
                        style={{
                            width: "100%",
                            height: "auto",
                            display: loading ? 'none' : 'block'
                        }}
                    />
                )}

                {/* Show loading spinner during initialization */}
                {loading && (
                    <Box
                        display="flex"
                        justifyContent="center"
                        alignItems="center"
                        height="100%"
                        bgcolor="action.hover"
                    >
                        <CircularProgress size={60} />
                    </Box>
                )}

                {/* Processing state */}
                {processing && (
                    <Box
                        display="flex"
                        justifyContent="center"
                        alignItems="center"
                        height="100%"
                        bgcolor="action.hover"
                        flexDirection="column"
                    >
                        <CircularProgress size={60} thickness={4} sx={{ mb: 3 }} />
                        <Typography variant="h6" color="text.primary">
                            Recognizing your face...
                        </Typography>
                    </Box>
                )}

                {/* Success state - shows without video */}
                {scanned && (
                    <Box
                        sx={{
                            position: 'relative',
                            height: '100%',
                            display: 'flex',
                            justifyContent: 'center',
                            alignItems: 'center',
                            backgroundColor: 'success.light',
                            overflow: 'hidden'
                        }}
                    >
                        <Box
                            sx={{
                                position: 'absolute',
                                top: 0,
                                left: 0,
                                width: '100%',
                                height: '100%',
                                backgroundColor: 'rgba(46, 125, 50, 0.3)',
                                display: 'flex',
                                flexDirection: 'column',
                                justifyContent: 'center',
                                alignItems: 'center'
                            }}
                        >
                            <CheckCircleIcon
                                sx={{
                                    fontSize: 80,
                                    color: 'white',
                                    mb: 2
                                }}
                            />
                            <Typography
                                variant="h5"
                                sx={{
                                    color: 'white',
                                    fontWeight: 'bold',
                                    textShadow: '0 2px 4px rgba(0,0,0,0.5)'
                                }}
                            >
                                Verification Successful
                            </Typography>
                        </Box>
                    </Box>
                )}
                
                {/* Error state */}
                {error && (
                    <Box
                        display="flex"
                        justifyContent="center"
                        alignItems="center"
                        height="100%"
                        bgcolor="action.hover"
                    >
                        <Alert severity="error" sx={{ width: '80%' }}>
                            {error}
                        </Alert>
                    </Box>
                )}

                <canvas ref={canvasRef} style={{ display: "none" }}></canvas>
            </Box>

            <Typography variant="caption" display="block" textAlign="center" color="text.secondary" mt={4}>
                For security purposes, we need to verify your identity
            </Typography>
            
            <Box textAlign="center">
                {error ? (
                    <Button
                        variant="contained"
                        size="large"
                        startIcon={<CameraIcon />}
                        onClick={restartCamera}
                        sx={{
                            px: 4,
                            py: 1.5,
                            borderRadius: '8px',
                            textTransform: 'none',
                            fontSize: '1rem'
                        }}
                    >
                        Try Again
                    </Button>
                ) : !scanned && !processing && (
                    <Button
                        variant="contained"
                        size="large"
                        startIcon={<CameraIcon />}
                        onClick={captureFaceData}
                        disabled={loading}
                        sx={{
                            px: 4,
                            py: 1.5,
                            borderRadius: '8px',
                            textTransform: 'none',
                            fontSize: '1rem'
                        }}
                    >
                        {loading ? 'Preparing Camera...' : 'Capture Image'}
                    </Button>
                )}
            </Box>
        </Container>
    );
};

export default FaceScan;