import React from 'react';
import { useTheme } from './ThemeContext'; // Verify context path
import vid from "../files/video.mp4"; // Dark theme video
import vid1 from "../files/light.mp4"; // Light theme video

const BackgroundVideo = () => {
    const { isDarkMode } = useTheme();

    // Force React to re-mount the video element when theme changes
    return (
        <video
            key={isDarkMode ? "dark-video" : "light-video"} // 🔑 Key forces re-render
            className="video m-0 p-0"
            autoPlay
            muted
            loop
            style={{
                position: 'absolute',
                top: 0,
                left: 0,
                width: '100%',
                height: '100%',
                objectFit: 'cover',
                zIndex: -1,
            }}
        >
            <source src={isDarkMode ? vid : vid1} type="video/mp4" />
            Your browser does not support the video tag.
        </video>
    );
};

export default BackgroundVideo;