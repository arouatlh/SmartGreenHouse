// Login.jsx
import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { loginUser } from "../services/api";
import "../Styles/login.css";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showError, setShowError] = useState(false);
  const navigate = useNavigate();

  const onSubmit = async (e) => {
  e.preventDefault();

  try {
    const data = await loginUser(email, password);

    localStorage.setItem("access_token", data.access_token);
    localStorage.setItem("refresh_token", data.refresh_token);

    setShowError(false);
    navigate("/dashboard");
  } catch (err) {
    setShowError(true);
  }
};


  return (
    <div className="container">
      <div className="brand">
        <div className="logo">🌱</div>
        <h1>Smart Green House</h1>
        <p>Smart Greenhouse Management System</p>
      </div>

      <div className="card">
        <h2>Welcome Back</h2>
        <p className="subtitle">Enter your credentials to access your dashboard.</p>

        <form onSubmit={onSubmit}>
          <label>Email</label>
          <input
            type="email"
            required
            value={email}
            placeholder="admin@smartgreenhouse.com"
            onChange={(e) => setEmail(e.target.value)}
          />

          <label>Password</label>
          <input
            type="password"
            required
            value={password}
            placeholder="••••••••"
            onChange={(e) => setPassword(e.target.value)}
          />

          <button type="submit">Log In</button>

          {showError && <p className="error">Invalid email or password</p>}

          <p style={{ marginTop: 12, textAlign: "center" }}>
            No account? <Link to="/signup">Sign up</Link>
          </p>
        </form>
      </div>
    </div>
  );
}
