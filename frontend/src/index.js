import React from 'react';
import ReactDOM from 'react-dom/client'; // Ensure you are using the correct import
import App from './App';
import 'bootstrap/dist/css/bootstrap.min.css'; // Import Bootstrap CSS
import './styles.css'; // Import the global CSS

const root = ReactDOM.createRoot(document.getElementById('root')); // Use createRoot for React 18
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);