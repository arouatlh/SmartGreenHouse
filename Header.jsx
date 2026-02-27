import { NavLink } from "react-router-dom";

export default function Header() {
  // NavLink automatically adds "active" based on route
    const linkClass = ({ isActive }) => `link ${isActive ? "active" : ""}`;

return (
    <header className="header">
        <div className="logo">
            <h2>Smart Green House</h2>
            <p>Green House Management System</p>
        </div>

    <nav className="menu">
        <NavLink to="/dashboard" className={linkClass}>
            <span className="icon">🏠</span>
            <span className="title">Dashboard</span>
        </NavLink>

        <NavLink to="/control" className={linkClass}>
            <span className="icon">🎛️</span>
            <span className="title">Control</span>
        </NavLink>

        <NavLink to="/analytics" className={linkClass}>
            <span className="icon">📊</span>
            <span className="title">Analytics</span>
        </NavLink>

        <NavLink to="/settings" className={linkClass}>
            <span className="icon">⚙️</span>
            <span className="title">Settings</span>
        </NavLink>

        {/* Logout just navigates to login */}
        <button
  className="link"
  onClick={() => {
    localStorage.removeItem("access_token");
    localStorage.removeItem("refresh_token");
    window.location.href = "/login";
  }}
>
  <span className="icon">🚪</span>
  <span className="title">Logout</span>
</button>

        </nav>
    </header>
    );
}
