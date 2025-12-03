import React, { useState, useEffect, useCallback } from 'react';
import Box from '@mui/material/Box';
import Modal from '@mui/material/Modal';
import Button from '@mui/material/Button';
import TextField from '@mui/material/TextField';
import Typography from '@mui/material/Typography';
import UserNav from '../NavBar/UserNav';
import { getSessionWithExpiry, clearSession } from '../../utils/sessionManager';
import CryptoJS from 'crypto-js';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

const UserApi = () => {
    const [apis, setApis] = useState([]);
    const [openModal, setOpenModal] = useState(false);
    const [projectName, setProjectName] = useState('');
    const [domainAllowed, setDomainAllowed] = useState('all');
    const [error, setError] = useState('');
    const ENCRYPTION_KEY = process.env.REACT_APP_ENCRYPTION_KEY || 'EVOd/1ytp2RnK9SSzfm6qYfY/FqtUopSi3+K/SeAAnk=';

    const navigate = useNavigate();

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

    useEffect(() => {
        fetchApis();
    }, []);

    //   useEffect(() => {
    //     async function checkLogin() {
    //       const Session = getSessionWithExpiry('secureSession');
    //       if (Session) {
    //         const encryptedSession = encryptData(Session)
    //         try {
    //           const res = await axios.post('http://localhost:5000/api/verify-session', { encryptedSession }, { timeout: 10000 });
    //           if (res.data.success) {
    //             console.log('Session verified successfully');
    //           } else {
    //             navigate('/Login');
    //             clearSession('secureSession');
    //           }
    //         } catch (err) {
    //             console.error('Session verification failed:', err);
    //             setError('Session expired or invalid. Please log in again.');
    //             navigate('/Login');
    //             clearSession('secureSession');
    //         }
    //       }
    //     }
    //     checkLogin();
    //   }, [navigate]);

    const fetchApis = async () => {
        try {
            const encryptedSession = encryptData(getSessionWithExpiry('secureSession'));
            const response = await axios.get('http://localhost:5000/api/user-apis', {
                headers: { 'X-Encrypted-Session': encryptedSession }
            });
            if (response.data.success) {
                setApis(response.data.apis);
                setError('');
            } else {
                setError(response.data.message);
            }
        } catch (error) {
            setError('Failed to fetch APIs');
            console.error('Error fetching APIs:', error);
        }
    };

    const handleCreateApi = async () => {
        if (!projectName.trim()) {
            setError('Project name is required');
            return;
        }
        try {
            const encryptedSession = encryptData(getSessionWithExpiry('secureSession'));
            const response = await axios.post('http://localhost:5000/api/create-api', {
                encryptedSession,
                project_name: projectName,
                domain_allowed: domainAllowed
            });
            if (response.data.success) {
                setApis([...apis, response.data.api]);
                setOpenModal(false);
                setProjectName('');
                setDomainAllowed('all');
                setError('');
            } else {
                setError(response.data.message);
            }
        } catch (error) {
            setError('Failed to create API');
            console.error('Error creating API:', error);
        }
    };

    return (
        <div style={{ display: 'flex', height: '100vh' }} className='pt-5'>
            <Box sx={{ width: '60px', bgcolor: '#f5f5f5' }}>
                <UserNav />
            </Box>
            <Box sx={{ flexGrow: 1, bgcolor: '#fafafa' }} className='pt-5'>
                {/* Center section, empty for now */}
            </Box>
            <Box sx={{ width: '300px', padding: '20px', bgcolor: '#ffffff', borderLeft: '1px solid #ddd' }} className='pt-5'>
                <Typography variant="h6" gutterBottom>User APIs</Typography>
                {error && <Typography color="error">{error}</Typography>}
                <Button variant="contained" color="primary" onClick={() => setOpenModal(true)} sx={{ mb: 2 }}>
                    Create New API
                </Button>
                {apis.length === 0 ? (
                    <Typography>No APIs found</Typography>
                ) : (
                    <ul style={{ listStyle: 'none', padding: 0 }}>
                        {apis.map(api => (
                            <li key={api.id} style={{ marginBottom: '10px', padding: '10px', border: '1px solid #eee', borderRadius: '4px' }}>
                                <Typography><strong>Project:</strong> {api.project_name}</Typography>
                                <Typography><strong>Domain:</strong> {api.domain_allowed}</Typography>
                                <Typography><strong>Created:</strong> {new Date(api.created_at).toLocaleString()}</Typography>
                            </li>
                        ))}
                    </ul>
                )}
                <Modal open={openModal} onClose={() => setOpenModal(false)}>
                    <Box sx={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', width: 400, bgcolor: 'background.paper', boxShadow: 24, p: 4, borderRadius: 2 }}>
                        <Typography variant="h6" gutterBottom>Create New API</Typography>
                        {error && <Typography color="error" sx={{ mb: 2 }}>{error}</Typography>}
                        <TextField
                            label="Project Name"
                            value={projectName}
                            onChange={(e) => setProjectName(e.target.value)}
                            fullWidth
                            margin="normal"
                            required
                        />
                        <TextField
                            label="Domain Allowed"
                            value={domainAllowed}
                            onChange={(e) => setDomainAllowed(e.target.value)}
                            fullWidth
                            margin="normal"
                            helperText="Enter a domain or leave as 'all' for all origins"
                        />
                        <Box sx={{ mt: 2 }}>
                            <Button variant="contained" color="primary" onClick={handleCreateApi}>
                                Create
                            </Button>
                            <Button variant="outlined" color="secondary" onClick={() => { setOpenModal(false); setError(''); }} sx={{ ml: 2 }}>
                                Cancel
                            </Button>
                        </Box>
                    </Box>
                </Modal>
            </Box>
        </div>
    );
};

export default UserApi;