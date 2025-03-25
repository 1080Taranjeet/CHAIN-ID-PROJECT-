// src/components/ThemeToggle.js

import React from 'react';
import { Button } from '@mui/material';
import { MdLightMode, MdDarkMode } from 'react-icons/md'; // Import the icons
import { useTheme } from './ThemeContext'; // Import the theme context

const ThemeToggle = () => {
  const { toggleTheme, isDarkMode } = useTheme(); // Use the theme context

  return (
    <Button 
      variant="contained" 
      onClick={toggleTheme} 
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: '#1976d2', // Change background based on theme
        color: isDarkMode ? '#000' : '#fff', // Change text color based on theme
        borderRadius: '15px', // Smaller rounded corners
        padding: '3px 8px', // Further reduced padding for a smaller button
        transition: 'background-color 0.3s ease', // Smooth transition
        fontSize: '12px', // Smaller font size
      }}
    >
      {isDarkMode ? <MdDarkMode size={18} /> : <MdLightMode size={18} />} {/* Smaller icon size */}
    </Button>
  );
};

export default ThemeToggle;