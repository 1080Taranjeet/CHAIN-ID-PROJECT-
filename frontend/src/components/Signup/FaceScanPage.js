// src/pages/FaceScanPage.js

import React from 'react';
import { Typography, Paper } from '@mui/material';
import FaceScan from '../scanner/FaceScan';

const FaceScanPage = () => {
  return (
    <Paper elevation={3} style={{ padding: '20px', marginTop: '50px' }}>
      <Typography variant="h4" align="center" gutterBottom>
        Face Scan Authentication
      </Typography>
      <FaceScan />
    </Paper>
  );
};

export default FaceScanPage;