import React from 'react';
import { Container, Row, Col, Card } from 'react-bootstrap';
import { 
  Security, 
  Fingerprint, 
  Email, 
  Code, 
  Storage, 
  Cloud, 
  Lock, 
  Face, 
  VerifiedUser 
} from '@mui/icons-material';
import { Typography, Divider, Chip, Grid } from '@mui/material';
import "./AboutUs.css";

export default function AboutUs() {
  return (
    <Container className="about-us-container mt-5 pt-5">
      {/* Hero Section */}
      <Row className="hero-section mb-5">
        <Col>
          <Typography variant="h2" className="text-center mb-4">
            <Lock fontSize="large" /> About ChainID
          </Typography>
          <Typography variant="h5" className="text-center mb-4 text-muted">
            Revolutionizing Authentication with Biometrics & Blockchain
          </Typography>
        </Col>
      </Row>

      {/* Project Introduction */}
      <Card className="section-card mb-5">
        <Card.Body>
          <Typography variant="h4" className="mb-4">
            <Security className="mr-2" /> Our Mission
          </Typography>
          <Typography variant="body1" paragraph>
            In today's digital landscape, traditional password-only authentication is both a security liability and user frustration. ChainID addresses these challenges by implementing a multi-factor authentication system that combines:
          </Typography>
          
          <Grid container spacing={2} className="mt-4">
            <Grid item xs={12} md={4}>
              <div className="feature-box">
                <Email fontSize="large" />
                <Typography variant="h6">Email OTP</Typography>
                <Typography>Dynamic one-time passwords delivered to verified emails</Typography>
              </div>
            </Grid>
            <Grid item xs={12} md={4}>
              <div className="feature-box">
                <Face fontSize="large" />
                <Typography variant="h6">Biometric Verification</Typography>
                <Typography>Facial recognition & fingerprint authentication</Typography>
              </div>
            </Grid>
            <Grid item xs={12} md={4}>
              <div className="feature-box">
                <Storage fontSize="large" />
                <Typography variant="h6">Blockchain Security</Typography>
                <Typography>Tamper-proof session logging</Typography>
              </div>
            </Grid>
          </Grid>
        </Card.Body>
      </Card>

      {/* How It Works */}
      <Row className="mb-5">
        <Col>
          <Typography variant="h4" className="mb-4">
            <Fingerprint className="mr-2" /> How ChainID Works
          </Typography>
          <div className="process-steps">
            <div className="process-step">
              <div className="step-number">1</div>
              <div>
                <Typography variant="h6">Registration</Typography>
                <Typography>
                  Users register with email and biometric data (face/fingerprint). 
                  OTP verification ensures email validity. Biometrics are compressed 
                  into secure templates - raw images are never stored.
                </Typography>
              </div>
            </div>
            
            <Divider className="my-3" />
            
            <div className="process-step">
              <div className="step-number">2</div>
              <div>
                <Typography variant="h6">Login</Typography>
                <Typography>
                  Two-factor authentication: Email OTP verification followed by 
                  real-time biometric matching. System compares live input with 
                  stored templates using cosine/Euclidean thresholds.
                </Typography>
              </div>
            </div>
            
            <Divider className="my-3" />
            
            <div className="process-step">
              <div className="step-number">3</div>
              <div>
                <Typography variant="h6">Session Security</Typography>
                <Typography>
                  All authentication events are logged in an immutable blockchain. 
                  Proof-of-work mechanism ensures session integrity and prevents 
                  tampering.
                </Typography>
              </div>
            </div>
          </div>
        </Col>
      </Row>

      {/* Technology Stack */}
      <Card className="section-card mb-5">
        <Card.Body>
          <Typography variant="h4" className="mb-4">
            <Code className="mr-2" /> Technology Stack
          </Typography>
          
          <Row className="tech-stack">
            <Col md={4}>
              <Typography variant="h6" className="mt-3">
                <Cloud className="mr-2" /> Frontend
              </Typography>
              <div className="chips-container">
                <Chip label="React.js" variant="outlined" />
                <Chip label="Material-UI" variant="outlined" />
                <Chip label="Tailwind CSS" variant="outlined" />
              </div>
            </Col>
            
            <Col md={4}>
              <Typography variant="h6" className="mt-3">
                <Storage className="mr-2" /> Backend
              </Typography>
              <div className="chips-container">
                <Chip label="Python/Flask" variant="outlined" />
                <Chip label="PyMongo" variant="outlined" />
                <Chip label="DeepFace" variant="outlined" />
                <Chip label="AES-256 Encryption" variant="outlined" />
              </div>
            </Col>
            
            <Col md={4}>
              <Typography variant="h6" className="mt-3">
                <VerifiedUser className="mr-2" /> Infrastructure
              </Typography>
              <div className="chips-container">
                <Chip label="MongoDB" variant="outlined" />
                <Chip label="Docker" variant="outlined" />
                <Chip label="HTTPS/TLS" variant="outlined" />
              </div>
            </Col>
          </Row>
        </Card.Body>
      </Card>

      {/* Security Features */}
      <Row className="mb-5">
        <Col>
          <Typography variant="h4" className="mb-4">
            <Lock className="mr-2" /> Security Architecture
          </Typography>
          <div className="security-features">
            <div className="security-feature">
              <div className="security-icon">🔒</div>
              <div>
                <Typography variant="h6">Privacy-First Design</Typography>
                <Typography>
                  Stores biometric templates instead of raw images to protect 
                  user identity. AES-256 encryption for all sensitive data.
                </Typography>
              </div>
            </div>
            
            <div className="security-feature">
              <div className="security-icon">🛡️</div>
              <div>
                <Typography variant="h6">Blockchain Integrity</Typography>
                <Typography>
                  Session blockchain with proof-of-work validation ensures 
                  tamper-proof audit trails of all authentication events.
                </Typography>
              </div>
            </div>
            
            <div className="security-feature">
              <div className="security-icon">🚫</div>
              <div>
                <Typography variant="h6">Anti-Abuse Measures</Typography>
                <Typography>
                  Rate limiting (5 OTP requests/minute), device fingerprinting, 
                  and session expiration protocols.
                </Typography>
              </div>
            </div>
          </div>
        </Col>
      </Row>

      {/* Future Vision */}
      <Card className="section-card">
        <Card.Body>
          <Typography variant="h4" className="mb-4">
            🔮 Future Vision
          </Typography>
          <ul className="future-list">
            <li>Mobile app with native biometric support</li>
            <li>Advanced liveness detection for anti-spoofing</li>
            <li>Decentralized identity management</li>
            <li>Multi-language support</li>
            <li>Passwordless authentication ecosystems</li>
          </ul>
        </Card.Body>
      </Card>
    </Container>
  );
}