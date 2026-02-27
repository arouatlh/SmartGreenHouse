// frontend/src/Pages/Settings.jsx
import { useEffect, useState } from "react";
import Header from "../components/Header";
import "../styles/settings.css";

import {
  getMyAlertPreferences,
  updateMyAlertPreferences,
  listDevices,
  pairDevice,
  getSystemSettings,
  setDeviceControl,
  getAllDeviceControls,
  getCurrentUser,
  listUsers,
  deactivateUser,
  createUser,
  reactivateUser
} from "../services/api";

export default function Settings() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [toast, setToast] = useState(null);

  // ---------------- ADMIN STATE ----------------
  const [me, setMe] = useState(null);
  const [users, setUsers] = useState([]);
  const [userLoading, setUserLoading] = useState(false);

  const [newUser, setNewUser] = useState({
    username: "",
    email: "",
    password: "",
    role: "user"
  });

  // ---------------- ALERT PREFERENCES ----------------
  const [prefs, setPrefs] = useState({
    email_enabled: true,
    push_enabled: false,
    ph_alert: true,
    ec_alert: true,
    temp_alert: true,
    humidity_alert: true
  });

  // ---------------- DEVICES ----------------
  const [devices, setDevices] = useState([]);
  const [pairCode, setPairCode] = useState("");

  // ---------------- CONFIG ----------------
  const [config, setConfig] = useState({});

  // ---------------- CONTROLS ----------------
  const [controls, setControls] = useState({});

  // ---------------- INITIAL LOAD ----------------
  useEffect(() => {
    async function loadAll() {
      try {
        setLoading(true);
        setError("");

        const meRes = await getCurrentUser();
        setMe(meRes?.data || null);

        const prefRes = await getMyAlertPreferences();
        if (prefRes?.data) {
          setPrefs((p) => ({ ...p, ...prefRes.data }));
        }

        const devRes = await listDevices();
        setDevices(devRes?.data || []);

        const cfgRes = await getSystemSettings();
        setConfig(cfgRes?.data || {});

        const ctrlRes = await getAllDeviceControls();
        setControls(ctrlRes?.data || {});

        if (meRes?.data?.role === "admin") {
          await reloadUsers();
        }

        setLoading(false);
      } catch (e) {
        setLoading(false);
        setError(e?.message || "Failed to load settings");
      }
    }

    loadAll();
  }, []);

  // ---------------- TOAST AUTO CLEAR ----------------
  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(() => setToast(null), 2000);
    return () => clearTimeout(timer);
  }, [toast]);

  // ---------------- ALERT HANDLERS ----------------
  function setPref(key, value) {
    setPrefs((p) => ({ ...p, [key]: value }));
  }

  async function savePrefs() {
    try {
      await updateMyAlertPreferences(prefs);
      setToast({ type: "success", text: "Preferences saved" });
    } catch (e) {
      setToast({ type: "error", text: e?.message || "Failed to save preferences" });
    }
  }

  // ---------------- DEVICE HANDLERS ----------------
  async function doPair() {
    try {
      await pairDevice(pairCode.trim());
      setPairCode("");
      const devRes = await listDevices();
      setDevices(devRes?.data || []);
      setToast({ type: "success", text: "Device paired" });
    } catch (e) {
      setToast({ type: "error", text: e?.message || "Pairing failed" });
    }
  }

  async function toggleControl(deviceId, nextStatus) {
    try {
      await setDeviceControl(deviceId, nextStatus);
      const ctrlRes = await getAllDeviceControls();
      setControls(ctrlRes?.data || {});
      setToast({ type: "success", text: "Device updated" });
    } catch (e) {
      setToast({ type: "error", text: e?.message || "Failed to update device" });
    }
  }

  // ---------------- ADMIN FUNCTIONS ----------------
  async function reloadUsers() {
    try {
      setUserLoading(true);
      const uRes = await listUsers();
      setUsers(uRes?.data || []);
    } finally {
      setUserLoading(false);
    }
  }

  async function handleDeactivate(userId) {
    if (userId === me?.sub) {
      return setToast({ type: "error", text: "You cannot deactivate yourself" });
    }

    try {
      await deactivateUser(userId);
      setToast({ type: "success", text: "User deactivated" });
      await reloadUsers();
    } catch (e) {
      setToast({ type: "error", text: e?.message || "Failed to deactivate user" });
    }
  }

  async function handleReactivate(userId) {
    try {
      await reactivateUser(userId);
      setToast({ type: "success", text: "User reactivated" });
      await reloadUsers();
    } catch (e) {
      setToast({ type: "error", text: e?.message || "Failed to reactivate user" });
    }
  }

  async function handleCreateUser() {

  // 🔒 Prevent empty fields
  if (!newUser.username || !newUser.email || !newUser.password) {
    return setToast({
      type: "error",
      text: "Please fill in all fields"
    });
  }

  try {
    await createUser(newUser);

    setToast({
      type: "success",
      text: "User created successfully"
    });

    // reset form
    setNewUser({
      username: "",
      email: "",
      password: "",
      role: "user"
    });

    await reloadUsers();

  } catch (e) {
    setToast({
      type: "error",
      text: e?.message || "Failed to create user"
    });
  }
}

  const inputStyle = {
    padding: 10,
    borderRadius: 10,
    border: "1px solid #ddd"
  };

  return (
    <>
      <Header />

      {toast && <div className={`toast ${toast.type}`}>{toast.text}</div>}

      <main className="main">
        {loading && <div className="card wide">Loading Settings…</div>}

        {error && (
          <div className="card wide" style={{ border: "1px solid #fca5a5" }}>
            <b style={{ color: "#b91c1c" }}>Error:</b> {error}
          </div>
        )}

        <div className="dashboard">

          {/* ALERT PREFERENCES */}
          <div className="card wide">
            <h3>Alert Preferences</h3>
            <p className="subtitle">Control how you receive warnings.</p>

            <div className="actions">
              {Object.keys(prefs).map((key) => (
                <label className="toggle" key={key}>
                  <span>{key.replace("_", " ")}</span>
                  <input
                    type="checkbox"
                    checked={!!prefs[key]}
                    onChange={(e) => setPref(key, e.target.checked)}
                  />
                  <span className="slider"></span>
                </label>
              ))}
            </div>

            <button className="ai-btn" onClick={savePrefs} style={{ marginTop: 16 }}>
              Save Preferences
            </button>
          </div>

          {/* DEVICE MANAGEMENT */}
          <div className="card wide">
            <h3>IoT Device Management</h3>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 180px", gap: 12 }}>
  <input
    value={pairCode}
    onChange={(e) => setPairCode(e.target.value)}
    placeholder="Enter pair code"
    style={{
      padding: 12,
      borderRadius: 12,
      border: "1px solid #ddd"
    }}
  />
  <button className="ai-btn" onClick={doPair}>
    Pair Device
  </button>
</div>


            <div style={{ marginTop: 14 }}>
              {devices.map((d) => (
                <div key={d.id} style={{ display: "flex", justifyContent: "space-between" }}>
                  <span>{d.name || d.id}</span>
                  <span style={{ color: d.paired ? "#16a34a" : "#b91c1c" }}>
                    {d.paired ? "Paired" : "Not paired"}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* CONFIG */}
          <div className="card wide">
            <h3>Greenhouse Configuration</h3>
            <div>Mode: {config.mode || "-"}</div>
            <div>Target pH: {config.target_ph ?? "-"}</div>
            <div>Target EC: {config.target_ec ?? "-"}</div>
            <div>Light Intensity: {config.light_intensity ?? "-"}%</div>
            <div>Schedule: {config.light_on_time || "-"} → {config.light_off_time || "-"}</div>
          </div>

          {/* QUICK TOGGLES */}
          <div className="card wide">
            <h3>Quick Device Toggles</h3>
            {Object.keys(controls).map((id) => (
              <label className="toggle" key={id}>
                <span>{id}</span>
                <input
                  type="checkbox"
                  checked={!!controls[id]?.status}
                  onChange={() => toggleControl(id, !controls[id]?.status)}
                />
                <span className="slider"></span>
              </label>
            ))}
          </div>

          {/* ADMIN SECTION */}
{me?.role === "admin" && (
  <div
    style={{
      display: "grid",
      gridTemplateColumns: "400px 1fr",
      gap: 24,
      alignItems: "start"
    }}
  >
    {/* LEFT — CREATE USER */}
    <div className="card">
      <h3 style={{ marginBottom: 16 }}>Create New User</h3>

      <div style={{ display: "grid", gap: 12 }}>
        <input
          placeholder="Username"
          value={newUser.username}
          onChange={(e) =>
            setNewUser({ ...newUser, username: e.target.value })
          }
          style={inputStyle}
        />

        <input
          placeholder="Email"
          value={newUser.email}
          onChange={(e) =>
            setNewUser({ ...newUser, email: e.target.value })
          }
          style={inputStyle}
        />

        <input
          type="password"
          placeholder="Password"
          value={newUser.password}
          onChange={(e) =>
            setNewUser({ ...newUser, password: e.target.value })
          }
          style={inputStyle}
        />

        <select
          value={newUser.role}
          onChange={(e) =>
            setNewUser({ ...newUser, role: e.target.value })
          }
          style={inputStyle}
        >
          <option value="user">User</option>
          <option value="admin">Admin</option>
        </select>

        <button
          className="ai-btn"
          onClick={handleCreateUser}
        >
          Create User
        </button>
      </div>
    </div>

    {/* RIGHT — USER LIST */}
    <div className="card">
      <h3 style={{ marginBottom: 16 }}>User Accounts</h3>

      <div style={{ display: "grid", gap: 12 }}>
        {users.map((u) => (
          <div
            key={u.id}
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              padding: "14px 18px",
              background: "#f9fafb",
              borderRadius: 12
            }}
          >
            <div>
              <div style={{ fontWeight: 600 }}>{u.email}</div>
              <div style={{ fontSize: 13, color: "#6b7280" }}>
                {u.role} — {u.is_active ? "Active" : "Disabled"}
              </div>
            </div>

            {u.is_active ? (
              <button
                style={{
                  background: "#dc2626",
                  color: "white",
                  border: "none",
                  borderRadius: 8,
                  padding: "6px 14px",
                  cursor: "pointer"
                }}
                onClick={() => handleDeactivate(u.id)}
              >
                Deactivate
              </button>
            ) : (
              <button
                style={{
                  background: "#16a34a",
                  color: "white",
                  border: "none",
                  borderRadius: 8,
                  padding: "6px 14px",
                  cursor: "pointer"
                }}
                onClick={() => handleReactivate(u.id)}
              >
                Reactivate
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  </div>
)}


        </div>
      </main>
    </>
  );
}
