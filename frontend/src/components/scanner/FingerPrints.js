// src/components/scanner/FingerPrint.js

import React, { useState } from 'react';
import { Button, Typography, Alert } from '@mui/material';

const FingerPrint = ({ onFingerprint }) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const startFingerprintScan = () => {
    setLoading(true);
    setError(null);

    // Simulate fingerprint scanning process
    setTimeout(() => {
      const success = Math.random() > 0.5; // Randomly simulate success or failure
      setLoading(false);
      if (success) {
        onFingerprint('Fingerprint ID: 123456'); // Simulated fingerprint ID
      } else {
        setError('Fingerprint scan failed. Please try again.');
      }
    }, 2000); // Simulate a 2-second scan
  };

  return (
    <div style={{ textAlign: 'center' }}>
      <Button variant="contained" color="primary" onClick={startFingerprintScan} disabled={loading}>
        {loading ? 'Scanning...' : 'Scan Fingerprint'}
      </Button>
      {error && <Alert severity="error" style={{ marginTop: '10px' }}>{error}</Alert>}
    </div>
  );
};

export default FingerPrint;