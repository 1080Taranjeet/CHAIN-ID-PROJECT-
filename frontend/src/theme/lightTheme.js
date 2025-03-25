import { createTheme } from '@mui/material/styles';

export const lightTheme = createTheme({
  palette: {
    mode: 'light',
    primary: {
      main: '#1976d2', // Light theme primary color
    },
    secondary: {
      main: '#dc004e', // Light theme secondary color
    },
    background: {
      default: '#121212', // Dark theme background color
      secondary : "#ffffff", //light background
      hover:"#000000",
    },
    text: {
      primary: '#000000', // Light theme primary text color
      secondary: '#555555', // Light theme secondary text color
      hover: "#ffffff",
    },
    border: {
      main: '#000000', // white colur
    }
  },
});