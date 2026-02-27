// frontend/src/Pages/Control.jsx
import { useEffect, useState } from "react";
import Header from "../components/Header.jsx";
import "../styles/control.css";

import {
  setDeviceControl,
  updateModeAndTargets,
  getSystemSettings,
  getAllDeviceControls
} from "../services/api";

export default function Control() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [mode, setMode] = useState("Vegetative");

  const [switches, setSwitches] = useState({
    nftMainPump: false,
    dosingPumpA: false,
    circulationFan: false,
    fogger: false
  });

  const [lightIntensity, setLightIntensity] = useState(80);
  const [onTime, setOnTime] = useState("06:00");
  const [offTime, setOffTime] = useState("22:00");

  const [targetPh, setTargetPh] = useState(6.0);
  const [targetEc, setTargetEc] = useState(2.2);

  const toggle = (key) => setSwitches((p) => ({ ...p, [key]: !p[key] }));

  useEffect(() => {
    async function load() {
      try {
        setLoading(true);
        setError("");

        // 1) Load system config
        const settingsRes = await getSystemSettings();
        const cfg = settingsRes?.data || {};

        if (cfg.mode) setMode(cfg.mode);
        if (cfg.target_ph != null) setTargetPh(Number(cfg.target_ph));
        if (cfg.target_ec != null) setTargetEc(Number(cfg.target_ec));

        // light config
        if (cfg.light_intensity != null) setLightIntensity(Number(cfg.light_intensity));
        if (cfg.light_on_time) setOnTime(String(cfg.light_on_time));
        if (cfg.light_off_time) setOffTime(String(cfg.light_off_time));

        // 2) Load device statuses
        const controlsRes = await getAllDeviceControls();
        const controls = controlsRes?.data || {};

        setSwitches((prev) => ({
          ...prev,
          nftMainPump: Boolean(controls?.nft_main_pump?.status ?? prev.nftMainPump),
          dosingPumpA: Boolean(controls?.dosing_pump_a?.status ?? prev.dosingPumpA),
          circulationFan: Boolean(controls?.circulation_fan?.status ?? prev.circulationFan),
          fogger: Boolean(controls?.fogger?.status ?? prev.fogger)
        }));

        setLoading(false);
      } catch (e) {
        setLoading(false);
        setError(e?.message || "Failed to load control settings");
      }
    }

    load();
  }, []);

  const applyAll = async () => {
    try {
      setError("");

      // ✅ Save mode + targets + light settings (NOW actually reaches backend)
      await updateModeAndTargets({
        mode,
        target_ph: Number(targetPh),
        target_ec: Number(targetEc),
        light_intensity: Number(lightIntensity),
        light_on_time: String(onTime),
        light_off_time: String(offTime)
      });

      // ✅ Save device states
      await Promise.all([
        setDeviceControl("nft_main_pump", switches.nftMainPump),
        setDeviceControl("dosing_pump_a", switches.dosingPumpA),
        setDeviceControl("circulation_fan", switches.circulationFan),
        setDeviceControl("fogger", switches.fogger)
      ]);

      alert("Control settings saved to Firebase ✅");
    } catch (err) {
      setError(err?.message || "Failed to apply settings");
    }
  };

  return (
    <>
      <Header />

      <main className="main">
        {loading ? (
          <div className="card" style={{ marginBottom: 16 }}>
            Loading Control Panel…
          </div>
        ) : null}

        {error ? (
          <div className="card" style={{ marginBottom: 16, border: "1px solid #fca5a5" }}>
            <b style={{ color: "#b91c1c" }}>Error:</b> {error}
          </div>
        ) : null}

        <div className="container">
          {/* Greenhouse Mode */}
          <div className="card">
            <h2>Greenhouse Mode</h2>
            <p className="subtitle">Select the current growth phase.</p>

            <div className={`mode ${mode === "Seedling" ? "active" : ""}`} onClick={() => setMode("Seedling")}>
              Seedling<br /><span>18–22°C, 70–80% RH</span>
            </div>

            <div className={`mode ${mode === "Vegetative" ? "active" : ""}`} onClick={() => setMode("Vegetative")}>
              Vegetative<br /><span>24–28°C, 60–70% RH</span>
            </div>

            <div className={`mode ${mode === "Fruiting" ? "active" : ""}`} onClick={() => setMode("Fruiting")}>
              Fruiting<br /><span>26–30°C, 50–60% RH</span>
            </div>
          </div>

          {/* Pump Controls */}
          <div className="card">
            <h2>Pump Controls</h2>
            <p className="subtitle">Manage all system pumps.</p>

            <div className="control">
              <span>NFT Main Pump</span>
              <label className="switch">
                <input
                  type="checkbox"
                  checked={switches.nftMainPump}
                  onChange={() => toggle("nftMainPump")}
                />
                <span className="slider"></span>
              </label>
            </div>

            <div className="control">
              <span>Dosing Pump A</span>
              <label className="switch">
                <input
                  type="checkbox"
                  checked={switches.dosingPumpA}
                  onChange={() => toggle("dosingPumpA")}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>

          {/* Climate Controls */}
          <div className="card">
            <h2>Climate Controls</h2>
            <p className="subtitle">Manage fans and humidity.</p>

            <div className="control">
              <span>Circulation Fan</span>
              <label className="switch">
                <input
                  type="checkbox"
                  checked={switches.circulationFan}
                  onChange={() => toggle("circulationFan")}
                />
                <span className="slider"></span>
              </label>
            </div>

            <div className="control">
              <span>Fogger / Humidifier</span>
              <label className="switch">
                <input
                  type="checkbox"
                  checked={switches.fogger}
                  onChange={() => toggle("fogger")}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>

          {/* Grow Light Control */}
          <div className="card">
            <h2>Grow Light Control</h2>
            <p className="subtitle">Adjust light intensity and schedule.</p>

            <label>
              Light Intensity: <strong>{lightIntensity}%</strong>
            </label>

            <input
              type="range"
              min="0"
              max="100"
              value={lightIntensity}
              onChange={(e) => setLightIntensity(Number(e.target.value))}
            />

            <div className="time">
              <div>
                <label>ON Time</label>
                <input type="time" value={onTime} onChange={(e) => setOnTime(e.target.value)} />
              </div>
              <div>
                <label>OFF Time</label>
                <input type="time" value={offTime} onChange={(e) => setOffTime(e.target.value)} />
              </div>
            </div>
          </div>

          {/* Nutrient Management */}
          <div className="card">
            <h2>Nutrient Management</h2>
            <p className="subtitle">Set target pH and EC levels for the nutrient solution.</p>

            <div className="control">
              <span>Target pH</span>
              <strong>{targetPh.toFixed(1)}</strong>
            </div>

            <input
              type="range"
              min="4.0"
              max="7.5"
              step="0.1"
              value={targetPh}
              onChange={(e) => setTargetPh(Number(e.target.value))}
            />

            <div className="control" style={{ marginTop: 15 }}>
              <span>Target EC</span>
              <strong>{targetEc.toFixed(2)} mS/cm</strong>
            </div>

            <input
              type="range"
              min="0.5"
              max="3.5"
              step="0.1"
              value={targetEc}
              onChange={(e) => setTargetEc(Number(e.target.value))}
            />

            <button className="ai-btn" onClick={applyAll}>
              Apply All Settings
            </button>
          </div>
        </div>
      </main>
    </>
  );
}
