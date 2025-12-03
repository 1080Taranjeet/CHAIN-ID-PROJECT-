import React, { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { FaUserCircle, FaBars } from 'react-icons/fa';
import { MdOutlineApi } from 'react-icons/md';

const Sidebar = () => {
  const location = useLocation();
  const [collapsed, setCollapsed] = useState(true);

  const toggleSidebar = () => setCollapsed((prev) => !prev);

  const navItems = [
    { label: 'User Dashboard', path: '/User', icon: <FaUserCircle size={18} /> },
    { label: 'API Access', path: '/User/api', icon: <MdOutlineApi size={18} /> },
  ];

  const sidebarStyle = {
    position: 'fixed',
    top: 0,
    left: 0,
    width: collapsed ? '60px' : '220px',
    height: '100vh',
    backgroundColor: '#0f172a',
    color: '#fff',
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'space-between',
    alignItems: 'center',
    transition: 'width 0.3s ease',
    zIndex: 1000,
    boxShadow: '2px 0 6px rgba(0,0,0,0.2)',
    padding: '20px 0',
  };

  const navLinkContainer = {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    width: '100%',
    flexGrow: 1,
    justifyContent: 'center',
  };

  const linkStyle = {
    width: '85%',
    textDecoration: 'none',
    color: '#cbd5e1',
    fontSize: '14px',
    fontWeight: 500,
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    padding: '10px 15px',
    borderRadius: '10px',
    margin: '10px 0',
    transition: 'all 0.2s ease-in-out',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
  };

  const activeLinkStyle = {
    ...linkStyle,
    backgroundColor: '#2563eb',
    color: '#ffffff',
    fontWeight: 'bold',
  };

  const toggleBtnStyle = {
    color: '#fff',
    background: 'none',
    border: 'none',
    fontSize: '22px',
    cursor: 'pointer',
    marginBottom: '10px',
  };

  const bottomToggleContainer = {
    paddingBottom: '20px',
  };

  return (
    <div style={sidebarStyle}>
      <div style={navLinkContainer}>
        {navItems.map((item) => (
          <Link
            key={item.path}
            to={item.path}
            style={location.pathname === item.path ? activeLinkStyle : linkStyle}
          >
            {item.icon}
            {!collapsed && item.label}
          </Link>
        ))}
      </div>

      <div style={bottomToggleContainer}>
        <button onClick={toggleSidebar} style={toggleBtnStyle}>
          <FaBars />
        </button>
      </div>
    </div>
  );
};

export default Sidebar;
