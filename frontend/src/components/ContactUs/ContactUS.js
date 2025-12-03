import React, { useState } from 'react';
import { 
  Container, 
  TextField, 
  Button, 
  Typography, 
  Box, 
  Grid,
  useTheme,
  Card,
  CardContent,
  IconButton,
  InputAdornment
} from '@mui/material';
import { Link } from 'react-router-dom';
import { Email, Phone, LocationOn, Send, ArrowBack } from '@mui/icons-material';
import axios from 'axios';
import BackgroundVideo from '../../theme/BackgroundVideo';

function ContactUs() {
  const theme = useTheme();
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    subject: '',
    message: ''
  });
  const [errors, setErrors] = useState({});
  const [submitSuccess, setSubmitSuccess] = useState(false);
  const [loading, setLoading] = useState(false);
  const [apiError, setApiError] = useState('');

  const validate = () => {
    const newErrors = {};
    
    if (!formData.name.trim()) {
      newErrors.name = 'Name is required';
    }
    
    if (!formData.email) {
      newErrors.email = 'Email is required';
    } else if (!/^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}$/i.test(formData.email)) {
      newErrors.email = 'Invalid email address';
    }
    
    if (!formData.subject.trim()) {
      newErrors.subject = 'Subject is required';
    }
    
    if (!formData.message.trim()) {
      newErrors.message = 'Message is required';
    }
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: value
    });
    
    if (errors[name]) {
      setErrors({
        ...errors,
        [name]: null
      });
    }
    
    // Clear API errors when user types
    if (apiError) setApiError('');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validate()) return;
    
    setLoading(true);
    setApiError('');
    
    try {
      const response = await axios.post('http://localhost:5000/api/contact', formData);
      
      if (response.data.success) {
        setSubmitSuccess(true);
        setFormData({
          name: '',
          email: '',
          subject: '',
          message: ''
        });
        
        setTimeout(() => {
          setSubmitSuccess(false);
        }, 5000);
      } else {
        setApiError(response.data.message || 'Failed to send message');
      }
    } catch (error) {
      const errorMessage = error.response?.data?.message || 
                           error.message || 
                           'Network error. Please try again.';
      setApiError(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="scroll" id="contact-page">
      <div className="container-fluid p-0 m-0 d-flex scroll min-vh-100">
        <BackgroundVideo />
        
        <div className="d-flex align-items-center justify-content-center col-12 py-5 pt-5 mt-5">
          <Container maxWidth="lg" className="py-5">
            <Grid container spacing={4} justifyContent="center">
              <Grid item xs={12} md={5}>
                <Card sx={{ 
                  background: theme.palette.background.paper,
                  border: `1px solid ${theme.palette.primary.main}`,
                  borderRadius: '20px',
                  height: '100%',
                  boxShadow: '0 10px 30px rgba(0, 0, 0, 0.5)'
                }}>
                  <CardContent className="h-100 d-flex flex-column justify-content-between p-4 p-md-5">
                    <div>
                      <Typography 
                        variant="h3" 
                        component="h1" 
                        gutterBottom
                        sx={{ 
                          color: theme.palette.primary.main,
                          fontWeight: 'bold',
                          mb: 3
                        }}
                      >
                        Contact Us
                      </Typography>
                      
                      <Typography 
                        variant="body1" 
                        paragraph
                        sx={{ 
                          color: theme.palette.text.secondary,
                          fontSize: '1.1rem',
                          mb: 4
                        }}
                      >
                        Have questions or feedback? We'd love to hear from you! Our team is ready to assist you with any inquiries.
                      </Typography>
                      
                      <Box sx={{ mb: 3 }}>
                        <Box display="flex" alignItems="center" mb={2}>
                          <Email sx={{ color: theme.palette.secondary.main, mr: 2, fontSize: '2rem' }} />
                          <Box>
                            <Typography variant="body2" sx={{ color: theme.palette.text.secondary }}>
                              Email
                            </Typography>
                            <Typography variant="body1" sx={{ color: theme.palette.text.primary }}>
                              support@chainid.example.com
                            </Typography>
                          </Box>
                        </Box>
                        
                        <Box display="flex" alignItems="center" mb={2}>
                          <Phone sx={{ color: theme.palette.secondary.main, mr: 2, fontSize: '2rem' }} />
                          <Box>
                            <Typography variant="body2" sx={{ color: theme.palette.text.secondary }}>
                              Phone
                            </Typography>
                            <Typography variant="body1" sx={{ color: theme.palette.text.primary }}>
                              +1 (555) 123-4567
                            </Typography>
                          </Box>
                        </Box>
                        
                        <Box display="flex" alignItems="center">
                          <LocationOn sx={{ color: theme.palette.secondary.main, mr: 2, fontSize: '2rem' }} />
                          <Box>
                            <Typography variant="body2" sx={{ color: theme.palette.text.secondary }}>
                              Address
                            </Typography>
                            <Typography variant="body1" sx={{ color: theme.palette.text.primary }}>
                              123 Tech Park, Innovation City
                            </Typography>
                          </Box>
                        </Box>
                      </Box>
                    </div>
                    
                    <Box mt={4}>
                      <Typography variant="body2" sx={{ color: theme.palette.text.secondary }}>
                        Follow us on social media
                      </Typography>
                      <Box display="flex" mt={1}>
                        {['facebook', 'twitter', 'instagram', 'linkedin'].map((social) => (
                          <IconButton 
                            key={social}
                            sx={{ 
                              color: theme.palette.text.primary,
                              mr: 1,
                              border: `1px solid ${theme.palette.primary.main}`,
                              '&:hover': {
                                background: theme.palette.primary.main,
                                color: '#000'
                              }
                            }}
                          >
                            <span className={`fab fa-${social}`}></span>
                          </IconButton>
                        ))}
                      </Box>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
              
              <Grid item xs={12} md={7}>
                <Card sx={{ 
                  background: theme.palette.background.paper,
                  border: `1px solid ${theme.palette.primary.main}`,
                  borderRadius: '20px',
                  boxShadow: '0 10px 30px rgba(0, 0, 0, 0.5)'
                }}>
                  <CardContent className="p-4 p-md-5">
                    <Box 
                      component="form" 
                      onSubmit={handleSubmit}
                    >
                      {apiError && (
                        <Box mb={3} textAlign="center">
                          <Typography 
                            variant="body1" 
                            sx={{ 
                              color: theme.palette.error.main,
                              fontWeight: 'bold',
                              fontSize: '1.1rem',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center'
                            }}
                          >
                            <i className="fas fa-exclamation-circle mr-2"></i>
                            {apiError}
                          </Typography>
                        </Box>
                      )}
                      
                      <Grid container spacing={3}>
                        <Grid item xs={12} sm={6}>
                          <TextField
                            fullWidth
                            label="Your Name *"
                            name="name"
                            value={formData.name}
                            onChange={handleChange}
                            error={!!errors.name}
                            helperText={errors.name}
                            variant="outlined"
                            InputProps={{
                              startAdornment: (
                                <InputAdornment position="start">
                                  <i className="fas fa-user"></i>
                                </InputAdornment>
                              ),
                            }}
                            sx={{
                              '& .MuiInputLabel-root': { color: theme.palette.text.secondary },
                              '& .MuiOutlinedInput-root': {
                                '& fieldset': { borderColor: theme.palette.primary.main },
                                '&:hover fieldset': { borderColor: theme.palette.secondary.main },
                                '&.Mui-focused fieldset': { borderColor: theme.palette.secondary.main },
                              },
                              '& .MuiInputBase-input': { 
                                color: theme.palette.text.primary,
                                paddingLeft: '10px'
                              }
                            }}
                          />
                        </Grid>
                        
                        <Grid item xs={12} sm={6}>
                          <TextField
                            fullWidth
                            label="Email Address *"
                            name="email"
                            type="email"
                            value={formData.email}
                            onChange={handleChange}
                            error={!!errors.email}
                            helperText={errors.email}
                            variant="outlined"
                            InputProps={{
                              startAdornment: (
                                <InputAdornment position="start">
                                  <i className="fas fa-envelope"></i>
                                </InputAdornment>
                              ),
                            }}
                            sx={{
                              '& .MuiInputLabel-root': { color: theme.palette.text.secondary },
                              '& .MuiOutlinedInput-root': {
                                '& fieldset': { borderColor: theme.palette.primary.main },
                                '&:hover fieldset': { borderColor: theme.palette.secondary.main },
                                '&.Mui-focused fieldset': { borderColor: theme.palette.secondary.main },
                              },
                              '& .MuiInputBase-input': { 
                                color: theme.palette.text.primary,
                                paddingLeft: '10px'
                              }
                            }}
                          />
                        </Grid>
                        
                        <Grid item xs={12}>
                          <TextField
                            fullWidth
                            label="Subject *"
                            name="subject"
                            value={formData.subject}
                            onChange={handleChange}
                            error={!!errors.subject}
                            helperText={errors.subject}
                            variant="outlined"
                            InputProps={{
                              startAdornment: (
                                <InputAdornment position="start">
                                  <i className="fas fa-tag"></i>
                                </InputAdornment>
                              ),
                            }}
                            sx={{
                              '& .MuiInputLabel-root': { color: theme.palette.text.secondary },
                              '& .MuiOutlinedInput-root': {
                                '& fieldset': { borderColor: theme.palette.primary.main },
                                '&:hover fieldset': { borderColor: theme.palette.secondary.main },
                                '&.Mui-focused fieldset': { borderColor: theme.palette.secondary.main },
                              },
                              '& .MuiInputBase-input': { 
                                color: theme.palette.text.primary,
                                paddingLeft: '10px'
                              }
                            }}
                          />
                        </Grid>
                        
                        <Grid item xs={12}>
                          <TextField
                            fullWidth
                            label="Your Message *"
                            name="message"
                            value={formData.message}
                            onChange={handleChange}
                            error={!!errors.message}
                            helperText={errors.message}
                            multiline
                            rows={6}
                            variant="outlined"
                            InputProps={{
                              startAdornment: (
                                <InputAdornment position="start" sx={{ alignItems: 'flex-start', mt: '8px' }}>
                                  <i className="fas fa-comment"></i>
                                </InputAdornment>
                              ),
                            }}
                            sx={{
                              '& .MuiInputLabel-root': { color: theme.palette.text.secondary },
                              '& .MuiOutlinedInput-root': {
                                '& fieldset': { borderColor: theme.palette.primary.main },
                                '&:hover fieldset': { borderColor: theme.palette.secondary.main },
                                '&.Mui-focused fieldset': { borderColor: theme.palette.secondary.main },
                                alignItems: 'flex-start'
                              },
                              '& .MuiInputBase-input': { 
                                color: theme.palette.text.primary,
                                paddingLeft: '10px'
                              }
                            }}
                          />
                        </Grid>
                      </Grid>
                      
                      <Box display="flex" justifyContent="center" mt={4}>
                        <Button
                          type="submit"
                          variant="contained"
                          color="primary"
                          size="large"
                          endIcon={<Send />}
                          sx={{ 
                            padding: theme.spacing(1.5, 4),
                            fontSize: '1.1rem',
                            background: 'linear-gradient(45deg, #FE6B8B 30%, #FF8E53 90%)',
                            boxShadow: '0 3px 5px 2px rgba(255, 105, 135, .3)',
                            '&:hover': {
                              background: 'linear-gradient(45deg, #FF8E53 30%, #FE6B8B 90%)',
                              boxShadow: '0 5px 10px 2px rgba(255, 105, 135, .5)',
                            }
                          }}
                          disabled={loading}
                        >
                          {loading ? 'Sending...' : 'SEND MESSAGE'}
                        </Button>
                      </Box>
                      
                      {submitSuccess && (
                        <Box mt={3} textAlign="center">
                          <Typography 
                            variant="body1" 
                            sx={{ 
                              color: theme.palette.success.main,
                              fontWeight: 'bold',
                              fontSize: '1.1rem',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center'
                            }}
                          >
                            <i className="fas fa-check-circle mr-2"></i>
                            Thank you! Your message has been sent successfully.
                          </Typography>
                        </Box>
                      )}
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
            
            <Box mt={4} textAlign="center">
              <Link to="/" style={{ textDecoration: 'none' }}>
                <Button
                  variant="outlined"
                  startIcon={<ArrowBack />}
                  sx={{
                    color: theme.palette.text.primary,
                    borderColor: theme.palette.primary.main,
                    '&:hover': {
                      borderColor: theme.palette.secondary.main,
                      backgroundColor: 'rgba(255,255,255,0.1)'
                    }
                  }}
                >
                  Back to Home
                </Button>
              </Link>
            </Box>
          </Container>
        </div>
      </div>
      
      {/* Font Awesome for icons */}
      <link 
        rel="stylesheet" 
        href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" 
        integrity="sha512-iecdLmaskl7CVkqkXNQ/ZH/XLlvWZOJyj7Yy7tcenmpD1ypASozpmT/E0iPtmFIB46ZmdtAc9eNBvH0H/ZpiBw==" 
        crossOrigin="anonymous" 
        referrerPolicy="no-referrer" 
      />
    </div>
  );
}

export default ContactUs;