// frontend/src/services/api.js
// Central API client (JWT + refresh token rotation)

const API_BASE = "https://greenhouse-api-198246796544.asia-southeast1.run.app/api"; 

function getAccessToken() {
  return localStorage.getItem("access_token");
}

function getRefreshToken() {
  return localStorage.getItem("refresh_token");
}

function setTokens({ access_token, refresh_token }) {
  if (access_token) localStorage.setItem("access_token", access_token);
  if (refresh_token) localStorage.setItem("refresh_token", refresh_token);
}

function clearTokens() {
  localStorage.removeItem("access_token");
  localStorage.removeItem("refresh_token");
}

let isRefreshing = false;
let refreshPromise = null;

async function refreshAccessToken() {
  if (isRefreshing) return refreshPromise;

  isRefreshing = true;

  refreshPromise = (async () => {
    try {
      const refresh_token = getRefreshToken();
      if (!refresh_token) throw new Error("No refresh token");

      const res = await fetch(`${API_BASE}/auth/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token, device: "Browser" })
      });

      if (!res.ok) {
        clearTokens();
        throw new Error("Refresh failed");
      }

      const data = await res.json();
      setTokens(data);
      return data.access_token;
    } finally {
      isRefreshing = false;
      refreshPromise = null;
    }
  })();

  return refreshPromise;
}

export async function registerUser(payload) {
  const res = await fetch(`${API_BASE}/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.detail || data?.message || "Signup failed");
  return data;
}

async function apiFetch(path, options = {}, retry = true) {
  const token = getAccessToken();

  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      ...(options.headers || {}),
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {})
    }
  });

  if (res.status === 401 && retry) {
    await refreshAccessToken();
    return apiFetch(path, options, false);
  }

  return res;
}

// -------------------- AUTH --------------------

export async function loginUser(email, password) {
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password, device: "Browser" })
  });

  if (!res.ok) throw new Error("Login failed");

  const data = await res.json();
  setTokens(data);
  return data;
}

export function logoutUser() {
  clearTokens();
}

// ✅ NEW: get current user payload (role, sub, etc.)
export async function getCurrentUser() {
  const res = await apiFetch("/auth/me", { method: "GET" });
  if (!res.ok) throw new Error("Failed to fetch current user");
  return res.json();
}

// -------------------- SENSORS --------------------

export async function getLatestSensor() {
  const res = await apiFetch("/sensor/latest", { method: "GET" });
  if (!res.ok) throw new Error("Failed to fetch latest sensor");
  return res.json();
}

export async function getSensorHistory(range = "24h") {
  const res = await apiFetch(`/sensor/history?range=${range}`, { method: "GET" });
  if (!res.ok) throw new Error("Failed to fetch sensor history");
  return res.json();
}

// -------------------- CONTROL (WRITE) --------------------

export async function setDeviceControl(device_id, status) {
  const res = await apiFetch("/control/control", {
    method: "POST",
    body: JSON.stringify({ device_id, status: Boolean(status) })
  });

  if (!res.ok) throw new Error("Failed to update device control");
  return res.json();
}

export async function updateModeAndTargets(payload) {
  const res = await apiFetch("/control/settings/mode", {
    method: "PUT",
    body: JSON.stringify(payload)
  });

  if (!res.ok) throw new Error("Failed to update mode/targets");
  return res.json();
}

export async function updateThresholds({ threshold_temp, ph_tolerance, ec_tolerance }) {
  const res = await apiFetch("/control/settings/thresholds", {
    method: "PUT",
    body: JSON.stringify({ threshold_temp, ph_tolerance, ec_tolerance })
  });

  if (!res.ok) throw new Error("Failed to update thresholds");
  return res.json();
}

// -------------------- CONTROL (READ) --------------------

export async function getSystemSettings() {
  const res = await apiFetch("/control/settings", { method: "GET" });
  if (!res.ok) throw new Error("Failed to fetch system settings");
  return res.json();
}

export async function getAllDeviceControls() {
  const res = await apiFetch("/control/control", { method: "GET" });
  if (!res.ok) throw new Error("Failed to fetch controls");
  return res.json();
}

// -------------------- NUTRIENTS --------------------

export async function createNutrientEvent({ nutrient_ml, source = "manual", timestamp = null }) {
  const res = await apiFetch("/nutrients/events", {
    method: "POST",
    body: JSON.stringify({ nutrient_ml, source, timestamp })
  });
  if (!res.ok) throw new Error("Failed to create nutrient event");
  return res.json();
}

export async function getNutrientUsage(range = "24h") {
  const res = await apiFetch(`/nutrients/usage?range=${range}`, { method: "GET" });
  if (!res.ok) throw new Error("Failed to fetch nutrient usage");
  return res.json();
}

// -------------------- GROWTH PHASE --------------------

export async function getGrowthPhaseHistory(range = "24h") {
  const res = await apiFetch(`/growth/history?range=${range}`, { method: "GET" });
  if (!res.ok) throw new Error("Failed to fetch growth phase history");
  return res.json();
}

// -------------------- SETTINGS (Alert Preferences) --------------------

export async function getMyAlertPreferences() {
  const res = await apiFetch("/settings/preferences", { method: "GET" });
  if (!res.ok) throw new Error("Failed to fetch preferences");
  return res.json();
}

export async function updateMyAlertPreferences(payload) {
  const res = await apiFetch("/settings/preferences", {
    method: "PUT",
    body: JSON.stringify(payload)
  });
  if (!res.ok) throw new Error("Failed to save preferences");
  return res.json();
}

// -------------------- DEVICES --------------------

export async function listDevices() {
  const res = await apiFetch("/devices", { method: "GET" });
  if (!res.ok) throw new Error("Failed to fetch devices");
  return res.json();
}

export async function pairDevice(pair_code) {
  const res = await apiFetch("/devices/pair", {
    method: "POST",
    body: JSON.stringify({ pair_code })
  });

  // ✅ keep old logic, but show backend error detail if present
  if (!res.ok) {
    let detail = "Failed to pair device";
    try {
      const err = await res.json();
      detail = err?.detail || err?.message || detail;
    } catch {}
    throw new Error(detail);
  }

  return res.json();
}

// -------------------- USERS (Admin) --------------------
// ✅ NEW: list users
export async function listUsers() {
  const res = await apiFetch("/users", { method: "GET" });
  if (!res.ok) throw new Error("Failed to fetch users");
  return res.json();
}

// ✅ NEW: deactivate user
export async function deactivateUser(user_id) {
  const res = await apiFetch(`/users/${user_id}/deactivate`, { method: "PUT" });

  if (!res.ok) {
    let detail = "Failed to deactivate user";
    try {
      const err = await res.json();
      detail = err?.detail || err?.message || detail;
    } catch {}
    throw new Error(detail);
  }

  return res.json();
}

export async function createUser(payload) {
  console.log("CREATE USER PAYLOAD:", payload);

  const res = await apiFetch("/users/", {
    method: "POST",
    body: JSON.stringify(payload)
  });

  const data = await res.json().catch(() => ({}));

  console.log("CREATE USER RESPONSE:", data);

  if (!res.ok) {
    throw new Error(JSON.stringify(data));
  }

  return data;
}



export async function reactivateUser(user_id) {
  const res = await apiFetch(`/users/${user_id}/reactivate`, {
    method: "PUT"
  });

  if (!res.ok) {
    const err = await res.json();
    throw new Error(err?.detail || "Failed to reactivate user");
  }

  return res.json();
}
