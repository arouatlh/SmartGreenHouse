// frontend/src/Pages/Analytics.jsx
import { useEffect, useState } from "react";
import Header from "../components/Header.jsx";
import SensorCard from "../components/SensorCard.jsx";
import TrendChart from "../Components/TrendChart.jsx";
import "../styles/dashboard.css";

import {
  getSensorHistory,
  getNutrientUsage,
  getGrowthPhaseHistory
} from "../services/api";

export default function Analytics() {
  // -----------------------------
  // CARD VALUES (kept)
  // -----------------------------
  const [s, setS] = useState({
    ph: 0,
    ec: 0,
    waterTemp: 0,
    nutrient: 0, // backend sensors not sending this; we handle nutrient usage separately
    airTemp: 0,
    humidity: 0,
    light: 0,
    flow: 0
  });

  // -----------------------------
  // SENSOR HISTORY (for charts)
  // -----------------------------
  const [history, setHistory] = useState([]);

  // -----------------------------
  // NUTRIENT USAGE EVENTS (NEW)
  // -----------------------------
  const [nutrientEvents, setNutrientEvents] = useState([]);
  const [nutrientTotalMl, setNutrientTotalMl] = useState(0);

  // -----------------------------
  // GROWTH PHASE TIMELINE (NEW)
  // -----------------------------
  const [growthTimeline, setGrowthTimeline] = useState([]);

  // -----------------------------
  // UI STATE (kept)
  // -----------------------------
  const [actions, setActions] = useState({
    mainPump: true,
    growLights: true,
    ventilation: false,
    autoDosing: true
  });

  const [range, setRange] = useState("24h");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const toggleAction = (key) =>
    setActions((prev) => ({ ...prev, [key]: !prev[key] }));

  // ✅ SAFE average
  function safeAvg(list, key, decimals = 2) {
    const nums = list
      .map((x) => Number(x?.[key]))
      .filter((n) => Number.isFinite(n));

    if (!nums.length) return 0;
    const mean = nums.reduce((a, b) => a + b, 0) / nums.length;
    return Number(mean.toFixed(decimals));
  }

  // ✅ label for charts
  function toLabel(ts) {
    if (!ts) return "";
    const d = new Date(ts);
    if (Number.isNaN(d.getTime())) return String(ts);
    if (range === "24h") return d.toLocaleTimeString();
    return d.toLocaleDateString();
  }

  // -----------------------------
  // Fetch EVERYTHING for analytics
  // -----------------------------
  useEffect(() => {
    async function fetchAnalytics() {
      try {
        setLoading(true);
        setError("");

        // 1) Sensor history
        const sensorRes = await getSensorHistory(range);
        const sensorData = sensorRes?.data || [];
        setHistory(sensorData);

        if (sensorData.length) {
          setS({
            ph: safeAvg(sensorData, "ph"),
            ec: safeAvg(sensorData, "ec"),
            waterTemp: safeAvg(sensorData, "water_temp", 1),
            nutrient: 0, // keep 0 (nutrient usage handled separately)
            airTemp: safeAvg(sensorData, "air_temp", 1),
            humidity: safeAvg(sensorData, "humidity", 1),
            light: safeAvg(sensorData, "light_intensity", 0),
            flow: safeAvg(sensorData, "flow_rate", 2)
          });
        }

        // 2) Nutrient usage
        const nutRes = await getNutrientUsage(range);
        setNutrientEvents(nutRes?.data || []);
        setNutrientTotalMl(Number(nutRes?.total_ml ?? 0));

        // 3) Growth phase timeline
        const growthRes = await getGrowthPhaseHistory(range);
        setGrowthTimeline(growthRes?.data || []);

        setLoading(false);
      } catch (err) {
        console.error("Analytics fetch failed:", err);
        setLoading(false);
        setError(err?.message || "Analytics fetch failed");
      }
    }

    fetchAnalytics();
  }, [range]);

  // -----------------------------
  // CHART DATA: sensors
  // -----------------------------
  const labels = history.map((h) => toLabel(h.timestamp));
  const phData = history.map((h) => Number(h.ph));
  const ecData = history.map((h) => Number(h.ec));
  const tempData = history.map((h) => Number(h.air_temp));
  const humidityData = history.map((h) => Number(h.humidity));

  // -----------------------------
  // CHART DATA: nutrient usage (ml per event)
  // -----------------------------
  const nutrientLabels = nutrientEvents.map((e) => toLabel(e.timestamp));
  const nutrientMlSeries = nutrientEvents.map((e) => Number(e.nutrient_ml));

  // -----------------------------
  // Render
  // -----------------------------
  return (
    <>
      <Header />

      <main className="main">
        <div className="dashboard">
          {/* Analytics Range block (kept) */}
          <div className="card wide">
            <h3>Analytics Range</h3>

            {loading ? (
              <p style={{ color: "#6b7280", marginTop: 10 }}>Loading…</p>
            ) : null}

            {error ? (
              <p style={{ color: "crimson", marginTop: 10 }}>{error}</p>
            ) : null}

            <select
              value={range}
              onChange={(e) => setRange(e.target.value)}
              style={{ padding: 8, marginTop: 10, width: "100%" }}
            >
              <option value="24h">Last 24 Hours</option>
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
            </select>
          </div>

          {/* Sensor blocks (kept) */}
          <SensorCard title="pH Level" iconClass="fa-solid fa-flask" value={s.ph} min={5.8} max={6.5} />
          <SensorCard title="EC Level" iconClass="fa-solid fa-bolt" value={s.ec} unit=" mS/cm" min={2} max={2.5} />
          <SensorCard title="Water Temp" iconClass="fa-solid fa-temperature-half" value={s.waterTemp} unit=" °C" min={20} max={25} />
          <SensorCard title="Nutrient Level" iconClass="fa-solid fa-droplet" value={s.nutrient} unit=" %" min={20} max={100} />
          <SensorCard title="Air Temperature" iconClass="fa-solid fa-temperature-high" value={s.airTemp} unit=" °C" min={24} max={28} />
          <SensorCard title="Humidity" iconClass="fa-solid fa-wind" value={s.humidity} unit=" %" min={60} max={80} />
          <SensorCard title="Light Intensity" iconClass="fa-solid fa-sun" value={s.light} unit=" lux" min={600} max={1000} />
          <SensorCard title="Flow Rate" iconClass="fa-solid fa-diagram-project" value={s.flow} unit=" L/min" min={2} max={3} />

          {/* QUICK ACTIONS block (kept exactly) */}
          <div className="card wide">
            <h3>Quick Actions</h3>
            <p className="subtitle">Toggle primary system functions.</p>

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

          {/* ✅ CHART 1: pH + EC */}
          <TrendChart
            title={`pH & EC Trend (${range})`}
            labels={labels}
            datasets={[
              { label: "pH", data: phData },
              { label: "EC", data: ecData }
            ]}
          />

          {/* ✅ CHART 2: Temp + Humidity */}
          <TrendChart
            title={`Temperature & Humidity Trend (${range})`}
            labels={labels}
            datasets={[
              { label: "Air Temp", data: tempData },
              { label: "Humidity", data: humidityData }
            ]}
          />

          {/* ✅ CHART 3: Nutrient Usage */}
          <TrendChart
            title={`Nutrient Usage (ml) — Total: ${nutrientTotalMl} ml`}
            labels={nutrientLabels}
            datasets={[
              { label: "Nutrient (ml)", data: nutrientMlSeries }
            ]}
          />

          {/* ✅ Growth Phase Timeline (simple, device not required) */}
          <div className="card wide">
            <h3>Growth Phase Timeline ({range})</h3>
            <p className="subtitle">
              Mode changes logged from Control Panel. Count: {growthTimeline.length}
            </p>

            {growthTimeline.length === 0 ? (
              <p style={{ color: "#6b7280", marginTop: 10 }}>
                No mode changes recorded in this time range.
              </p>
            ) : (
              <div style={{ marginTop: 10, display: "grid", gap: 10 }}>
                {growthTimeline.map((g) => (
                  <div
                    key={g.id}
                    style={{
                      background: "#f9fafb",
                      padding: 12,
                      borderRadius: 12,
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center"
                    }}
                  >
                    <b>{g.mode}</b>
                    <span style={{ color: "#6b7280", fontSize: 13 }}>
                      {toLabel(g.changed_at)}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* AI ANALYSIS block (kept exactly) */}
        <div className="card wide">
          <h2 className="predictive-title">Predictive AI Analysis</h2>
          <p className="predictive-description">
            Use AI to analyze recent sensor data and identify potential risks early.
            The system reviews the last 12 hours of data to predict issues and recommends
            proactive adjustments tailored to your plants current growth phase.
          </p>
          <button
            className="predictive-btn"
            onClick={() => alert("Predictive analysis (demo)")}
          >
            🤖 Run Predictive Analysis
          </button>
        </div>
      </main>
    </>
  );
}
