// src/components/scanner/FaceScan.js

import React, { useRef, useState, useEffect } from 'react';
import Webcam from 'react-webcam';
import { Typography, CircularProgress } from '@mui/material';

const FaceScan = () => {
  const webcamRef = useRef(null);
  const [imageSrc, setImageSrc] = useState(null);
  const [loading, setLoading] = useState(true);

  const capture = React.useCallback(() => {
    const image = webcamRef.current.getScreenshot();
    setImageSrc(image);
    setLoading(false); // Set loading to false after capturing the image
  }, [webcamRef]);

  useEffect(() => {
    // Automatically capture the image when the component mounts
    const timer = setTimeout(() => {
      capture();
    }, 1000); // Delay to allow the webcam to initialize

    return () => clearTimeout(timer); // Cleanup the timer on unmount
  }, [capture]);

  return (
    <div style={{ textAlign: 'center' }}>
      <Webcam
        audio={false}
        ref={webcamRef}
        screenshotFormat="image/jpeg"
        width={350}
      />
      {loading && <CircularProgress style={{ marginTop: '10px' }} />} {/* Show loading indicator */}
      {imageSrc && (
        <div>
          <Typography variant="h6">Scanned Face:</Typography>
          <img src={imageSrc} alt="Scanned Face" style={{ width: '350px', marginTop: '10px' }} />
        </div>
      )}
    </div>
  );
};

export default FaceScan;