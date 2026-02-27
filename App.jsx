// App.jsx
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";

import ProtectedRoute from "./Components/ProtectedRoute";

import Dashboard from "./Pages/Dashboard";
import Control from "./Pages/Control";
import Analytics from "./Pages/Analytics";
import Settings from "./Pages/Settings";
import Login from "./Pages/Login";
import Signup from "./Pages/Signup";

export default function App() {
    return (
    <BrowserRouter>
        <Routes>
        <Route path="/" element={<Navigate to="/login" replace />} />

        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<Signup />} />

       <Route
  path="/dashboard"
  element={
    <ProtectedRoute>
      <Dashboard />
    </ProtectedRoute>
  }
/>

<Route
  path="/control"
  element={
    <ProtectedRoute>
      <Control />
    </ProtectedRoute>
  }
/>

<Route
  path="/analytics"
  element={
    <ProtectedRoute>
      <Analytics />
    </ProtectedRoute>
  }
/>

<Route
  path="/settings"
  element={
    <ProtectedRoute>
      <Settings />
    </ProtectedRoute>
  }
/>


        <Route path="*" element={<Navigate to="/login" replace />} />
    </Routes>
    </BrowserRouter>
    );
}
