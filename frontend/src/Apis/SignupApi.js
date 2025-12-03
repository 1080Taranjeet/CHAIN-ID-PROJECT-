import React, { useState } from 'react';
import axios from 'axios';

const SignupAPi = () => {
  const [apiKey, setApiKey] = useState('');
  const [userId, setUserId] = useState('');
  const [verificationResult, setVerificationResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setVerificationResult(null);
    setError(null);

    try {
      const response = await axios.post('[invalid url, do not cite]' {
        api_key: apiKey,
        user_id: userId
      });

      if (!response.data.success) {
        setVerificationResult('Verification failed: ' + response.data.message);
      }
      // On success, do nothing as per the request
    } catch (err) {
      setError('An error occurred: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: '20px', maxWidth: '400px', margin: '0 auto' }}>
      <h2>Verify Credentials</h2>
      <form onSubmit={handleSubmit}>
        <div style={{ marginBottom: '10px' }}>
          <label>API Key:</label>
          <input
            type="text"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            required
            style={{ width: '100%', padding: '8px', marginTop: '5px' }}
          />
        </div>
        <div style={{ marginBottom: '10px' }}>
          <label>User ID:</label>
          <input
            type="text"
            value={userId}
            onChange={(e) => setUserId(e.target.value)}
            required
            style={{ width: '100%', padding: '8px', marginTop: '5px' }}
          />
        </div>
        <button type="submit" disabled={loading} style={{ padding: '10px', width: '100%' }}>
          {loading ? 'Verifying...' : 'Verify'}
        </button>
      </form>
      {verificationResult && <p style={{ marginTop: '10px' }}>{verificationResult}</p>}
      {error && <p style={{ color: 'red', marginTop: '10px' }}>{error}</p>}
    </div>
  );
};

export default SignupAPi;