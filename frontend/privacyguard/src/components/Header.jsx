import React from "react";

const Header = () => {
  return (
    <header className="header">
      <div className="header-content">
        <div className="logo-section">
          <div className="logo">🛡️</div>
          <div>
            <h1 className="title">PrivacyGuard</h1>
            <p className="subtitle">Network Threat Detection Tool</p>
          </div>
        </div>
        <div className="header-actions">
          <span className="status-badge status-safe">● System Active</span>
        </div>
      </div>
    </header>
  );
};

export default Header;
