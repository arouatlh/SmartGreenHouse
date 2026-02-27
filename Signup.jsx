// Signup.jsx
import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import "../styles/signing.css";

export default function Signup() {
    const navigate = useNavigate();

    const [form, setForm] = useState({
        firstName: "",
        lastName: "",
        email: "",
        phone: "",
        position: "",
        password: "",
        confirmPassword: ""
    });

    const [error, setError] = useState("");

    const set = (key, val) => setForm((p) => ({ ...p, [key]: val }));

    const onSubmit = (e) => {
        e.preventDefault();

    if (!form.firstName.trim()) return setError("First name is required.");
    if (!form.lastName.trim()) return setError("Last name is required.");
    if (!form.position) return setError("Please select a position.");
    if (!form.email.trim()) return setError("Email is required.");
    if (!form.phone.trim()) return setError("Phone number is required.");
    if (form.password.length < 6) return setError("Password must be at least 6 characters.");
    if (form.password !== form.confirmPassword) return setError("Passwords do not match.");

    setError("");
    navigate("/login");
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
            <form id="signinForm" onSubmit={onSubmit}>

            <label htmlFor="first-name">First Name</label>
            <input
            id="first-name"
            value={form.firstName}
            placeholder="Ahmed"
            onChange={(e) => set("firstName", e.target.value)}
            />

            <label htmlFor="last-name">Last Name</label>
            <input
            id="last-name"
            value={form.lastName}
            placeholder="Ali"
            onChange={(e) => set("lastName", e.target.value)}
            />

            <label htmlFor="email">Email</label>
            <input
            id="email"
            type="email"
            value={form.email}
            placeholder="admin@gmail.com"
            onChange={(e) => set("email", e.target.value)}
            />

            <label htmlFor="phone-number">Phone Number</label>
            <input
            id="phone-number"
            type="tel"
            value={form.phone}
            placeholder="01123456789"
            onChange={(e) => set("phone", e.target.value)}
            />

            <label htmlFor="position">Position</label>
            <select
            id="position"
            name="position"
            className="input"
            value={form.position}
            onChange={(e) => set("position", e.target.value)}
            required
            >

            <option value="" disabled>Select position</option>
            <option value="OWNER">Owner</option>
            <option value="MANAGER">Manager</option>
            <option value="TECH">Technician</option>
            <option value="STAFF">Staff</option>
        </select>

            <label>Password</label>
            <input
            type="password"
            value={form.password}
            placeholder="••••••••"
            onChange={(e) => set("password", e.target.value)}
            />

            <label>Confirm Password</label>
            <input
            type="password"
            value={form.confirmPassword}
            placeholder="••••••••"
            onChange={(e) => set("confirmPassword", e.target.value)}
            />

            <button type="submit">Sign In</button>

            {error && (
            <p className="error" id="errorMsg" style={{ display: "block" }}>
                {error}
            </p>
            )}

            <p style={{ marginTop: 12, textAlign: "center" }}>
                Already have an account? <Link to="/login">Log in</Link>
            </p>
        </form>
    </div>
</div>
    );
}
