// frontend/src/Pages/Dashboard.jsx

import { useEffect, useMemo, useState } from "react";
import Header from "../components/Header.jsx";
import SensorCard from "../components/SensorCard.jsx";
import TrendChart from "../Components/TrendChart.jsx";
import "../styles/dashboard.css";

import {
  getLatestSensor,
  getSensorHistory,
  setDeviceControl,
  getAllDeviceControls   // ✅ ADD THIS
} from "../services/api";


export default function Dashboard() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // -------------------------
  // SENSOR STATE
  // -------------------------
  const [s, setS] = useState({
    ph: 0,
    ec: 0,
    waterTemp: 0,
    nutrient: 0,
    airTemp: 0,
    humidity: 0,
    light: 0,
    flow: 0,
    timestamp: null
  });

  // -------------------------
  // HISTORY STATE (for charts)
  // -------------------------
  const [history, setHistory] = useState([]);

  // -------------------------
  // DEVICE CONTROL STATE
  // -------------------------

  const [actions, setActions] = useState({
    mainPump: false,
    growLights: false,
    ventilation: false,
    autoDosing: false
  });

  const deviceIdMap = useMemo(
    () => ({
      mainPump: "main_pump",
      growLights: "grow_lights",
      ventilation: "ventilation",
      autoDosing: "auto_dosing"
    }),
    []
  );

  // -------------------------
  // LOAD LATEST SENSOR
  // -------------------------
  async function loadLatest() {
    try {
      setError("");
      const res = await getLatestSensor();
      const d = res?.data || {};

      setS((prev) => ({
        ...prev,
        ph: Number(d.ph ?? 0),
        ec: Number(d.ec ?? 0),
        waterTemp: Number(d.water_temp ?? 0),
        airTemp: Number(d.air_temp ?? 0),
        humidity: Number(d.humidity ?? 0),
        light: Number(d.light_intensity ?? 0),
        flow: Number(d.flow_rate ?? 0),
        nutrient: Number(d.nutrient ?? prev.nutrient ?? 0),
        timestamp: d.timestamp ?? null
      }));

      setLoading(false);
    } catch (e) {
      setLoading(false);
      setError(e?.message || "Failed to load sensors");
    }
  }

  // -------------------------
  // LOAD HISTORY (24h)
  // -------------------------
  async function loadHistory() {
    try {
      const res = await getSensorHistory("24h");
      setHistory(res?.data || []);
    } catch (e) {
      console.error("History load failed:", e);
    }
  }

  // -------------------------
  // AUTO POLLING
  // -------------------------
  useEffect(() => {
    let timer;

    (async () => {
  await loadLatest();
  await loadHistory();
  await loadDeviceStatus();   // ✅ ADD THIS

  timer = setInterval(() => {
    loadLatest();
    loadHistory();
    loadDeviceStatus();       // ✅ ADD THIS
  }, 30000);
})();


    return () => {
      if (timer) clearInterval(timer);
    };
  }, []);

  async function loadDeviceStatus() {
  try {
    const res = await getAllDeviceControls();
    const controls = res?.data || {};

    setActions((prev) => ({
      ...prev,
      mainPump: Boolean(controls?.main_pump?.status ?? prev.mainPump),
      growLights: Boolean(controls?.grow_lights?.status ?? prev.growLights),
      ventilation: Boolean(controls?.ventilation?.status ?? prev.ventilation),
      autoDosing: Boolean(controls?.auto_dosing?.status ?? prev.autoDosing)
    }));
  } catch (e) {
    console.error("Failed to load device status:", e);
  }
}



  // -------------------------
  // DEVICE TOGGLE
  // -------------------------
  async function toggleAction(key) {
    const nextValue = !actions[key];

    // optimistic update
    setActions((prev) => ({ ...prev, [key]: nextValue }));

    try {
      const device_id = deviceIdMap[key];
      await setDeviceControl(device_id, nextValue);
    } catch (e) {
      // rollback
      setActions((prev) => ({ ...prev, [key]: !nextValue }));
      alert(e?.message || "Control update failed");
    }
  }

  // -------------------------
  // CHART DATA PREP
  // -------------------------
  const labels = history.map((h) =>
    new Date(h.timestamp).toLocaleTimeString()
  );

  const phData = history.map((h) => Number(h.ph));
  const ecData = history.map((h) => Number(h.ec));
  const tempData = history.map((h) => Number(h.air_temp));
  const humidityData = history.map((h) => Number(h.humidity));

  // -------------------------
  // RENDER
  // -------------------------
  return (
    <>
      <Header />

      <main className="main">
        {error && (
          <div className="card wide" style={{ border: "1px solid #fca5a5" }}>
            <b style={{ color: "#b91c1c" }}>Backend error:</b> {error}
          </div>
        )}

        <div className="dashboard">

          {/* SENSOR CARDS */}
          <SensorCard title="pH Level" iconClass="fa-solid fa-flask" value={s.ph} min={5.8} max={6.5} />
          <SensorCard title="EC Level" iconClass="fa-solid fa-bolt" value={s.ec} unit=" mS/cm" min={2} max={2.5} />
          <SensorCard title="Water Temp" iconClass="fa-solid fa-temperature-half" value={s.waterTemp} unit=" °C" min={20} max={25} />
          <SensorCard title="Nutrient Level" iconClass="fa-solid fa-droplet" value={s.nutrient} unit=" %" min={20} max={100} />
          <SensorCard title="Air Temperature" iconClass="fa-solid fa-temperature-high" value={s.airTemp} unit=" °C" min={24} max={28} />
          <SensorCard title="Humidity" iconClass="fa-solid fa-wind" value={s.humidity} unit=" %" min={60} max={80} />
          <SensorCard title="Light Intensity" iconClass="fa-solid fa-sun" value={s.light} unit=" lux" min={600} max={1000} />
          <SensorCard title="Flow Rate" iconClass="fa-solid fa-diagram-project" value={s.flow} unit=" L/min" min={2} max={3} />

          {/* QUICK ACTIONS */}
          <div className="card wide">
            <h3>Quick Actions</h3>
            <p className="subtitle">
              Toggle primary system functions.
              {s.timestamp && (
                <span style={{ marginLeft: 10, fontSize: 12, color: "#6b7280" }}>
                  Last sensor timestamp: {String(s.timestamp)}
                </span>
              )}
              {loading && (
                <span style={{ marginLeft: 10, fontSize: 12, color: "#6b7280" }}>
                  Loading…
                </span>
              )}
            </p>

            <div className="actions">
              <label className="toggle">
                <span>Main Pump</span>
                <input
                  type="checkbox"
                  checked={actions.mainPump}
                  onChange={() => toggleAction("mainPump")}
                />
                <span className="slider"></span>
              </label>

              <label className="toggle">
                <span>Grow Lights</span>
                <input
                  type="checkbox"
                  checked={actions.growLights}
                  onChange={() => toggleAction("growLights")}
                />
                <span className="slider"></span>
              </label>

              <label className="toggle">
                <span>Ventilation</span>
                <input
                  type="checkbox"
                  checked={actions.ventilation}
                  onChange={() => toggleAction("ventilation")}
                />
                <span className="slider"></span>
              </label>

              <label className="toggle">
                <span>Auto Dosing</span>
                <input
                  type="checkbox"
                  checked={actions.autoDosing}
                  onChange={() => toggleAction("autoDosing")}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>

          {/* AI BLOCK */}
          <div className="card wide">
            <h2 className="predictive-title">Predictive AI Analysis</h2>
            <p className="predictive-description">
              Use AI to analyze recent sensor data and identify potential risks early.
            </p>
            <button
              className="predictive-btn"
              onClick={() => alert("Predictive analysis (demo)")}
            >
              🤖 Run Predictive Analysis
            </button>
          </div>

          {/* CHART 1 */}
          <TrendChart
            title="pH & EC Trend (Last 24h)"
            labels={labels}
            datasets={[
              {
                label: "pH",
                data: phData,
                borderColor: "#12b76a",
                backgroundColor: "rgba(18,183,106,0.1)"
              },
              {
                label: "EC",
                data: ecData,
                borderColor: "#3b82f6",
                backgroundColor: "rgba(59,130,246,0.1)"
              }
            ]}
          />

          {/* CHART 2 */}
          <TrendChart
            title="Temperature & Humidity Trend (Last 24h)"
            labels={labels}
            datasets={[
              {
                label: "Air Temp",
                data: tempData,
                borderColor: "#f97316",
                backgroundColor: "rgba(249,115,22,0.1)"
              },
              {
                label: "Humidity",
                data: humidityData,
                borderColor: "#06b6d4",
                backgroundColor: "rgba(6,182,212,0.1)"
              }
            ]}
          />

        </div>
      </main>
    </>
  );
}
