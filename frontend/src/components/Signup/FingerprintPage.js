// src/pages/FingerprintPage.js

import React, { useState } from 'react';
import { Typography, Paper, Button, Alert } from '@mui/material';
import FingerPrint from '../scanner/FingerPrints';

const FingerprintPage = () => {
  const [fingerprintData, setFingerprintData] = useState(null);

  const handleFingerprint = (data) => {
    setFingerprintData(data);
  };

  return (
    <Paper elevation={3} style={{ padding: '20px', marginTop: '50px' }}>
      <Typography variant="h4" align="center" gutterBottom>
        Fingerprint Authentication
      </Typography>
      <FingerPrint onFingerprint={handleFingerprint} />
      {fingerprintData && (
        <Alert severity="success" style={{ marginTop: '20px' }}>
          Fingerprint scanned successfully!
        </Alert>
      )}
    </Paper>
  );
};

export default FingerprintPage;