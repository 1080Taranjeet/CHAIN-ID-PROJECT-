import { createTheme } from '@mui/material/styles';

export const darkTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#1976d2', // Dark theme primary color
    },
    secondary: {
      main: '#f48fb1', // Dark theme secondary color
    },
    background: {
      default: '#ffffff', // Light theme background color
      secondary: '#000000', // dark background
      hover:"#ffffff",
    },
    text: {
      primary: '#ffffff', // Dark theme primary text color
      secondary: '#cccccc', // Dark theme secondary text color
      hover:"#000000"
    },
    border: {
      main: '#ffffff', // white colur
    }
  },
});