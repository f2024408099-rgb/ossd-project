// CyberTrace Master JS State & Network Controller

const API_BASE = "/api";

// JWT and User state helpers
function getToken() {
  return localStorage.getItem("cybertrace_token");
}

function getUserFromToken() {
  const userStr = localStorage.getItem("cybertrace_user");
  if (!userStr) return null;
  try {
    return JSON.parse(userStr);
  } catch (e) {
    return null;
  }
}

function saveToken(token, user) {
  localStorage.setItem("cybertrace_token", token);
  localStorage.setItem("cybertrace_user", JSON.stringify(user));
}

function removeToken() {
  localStorage.removeItem("cybertrace_token");
  localStorage.removeItem("cybertrace_user");
}

// Wrapper for API calls
async function apiRequest(endpoint, options = {}) {
  const token = getToken();
  const headers = {
    "Content-Type": "application/json",
    ...options.headers
  };

  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const config = {
    ...options,
    headers
  };

  const url = `${API_BASE}/${endpoint}`;
  const response = await fetch(url, config);
  
  if (response.status === 401) {
    // If token expired or invalid, auto logout on API failures
    removeToken();
    if (!window.location.pathname.includes("login.html") && !window.location.pathname.includes("register.html") && window.location.pathname !== "/" && window.location.pathname !== "/login" && window.location.pathname !== "/register") {
      window.location.href = "login.html";
    }
  }

  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.detail || data.error || data.message || `Request failed with status ${response.status}`);
  }
  
  return data;
}

// Dynamically inject uniform navbar on all desktop hubs
function renderNavbar() {
  const navbarContainer = document.getElementById("cybertrace-navbar");
  if (!navbarContainer) return;

  const currentUser = getUserFromToken();
  const isLoggedIn = !!currentUser;

  let navLinks = "";
  if (isLoggedIn) {
    navLinks = `
      <li class="nav-item">
        <a class="nav-link ${isActiveLink('dashboard.html') || isActiveLink('/dashboard') ? 'active fw-bold' : ''}" href="dashboard.html"><i class="bi bi-speedometer2"></i> Incident Desk</a>
      </li>
      <li class="nav-item">
        <a class="nav-link ${isActiveLink('feed.html') || isActiveLink('/feed') ? 'active fw-bold' : ''}" href="feed.html"><i class="bi bi-shield-shaded"></i> Threat Feed</a>
      </li>
      <li class="nav-item">
        <a class="nav-link ${isActiveLink('profile.html') || isActiveLink('/profile') ? 'active fw-bold' : ''}" href="profile.html"><i class="bi bi-person-fill"></i> User Panel</a>
      </li>
    `;

    // High privilege administrative tab
    if (currentUser.role === "admin") {
      navLinks += `
        <li class="nav-item">
          <a class="nav-link text-warning border border-warning border-opacity-30 px-2 rounded ms-lg-2 ${isActiveLink('admin.html') || isActiveLink('/admin') ? 'active fw-bold' : ''}" href="admin.html"><i class="bi bi-cpu-fill"></i> SOC panel</a>
        </li>
      `;
    }
  }

  const authSection = isLoggedIn 
    ? `
      <div class="d-flex align-items-center gap-3">
        <span class="text-secondary small d-none d-md-inline">
          Analyst Code: <strong class="text-info">${currentUser.display_name}</strong> (${currentUser.role.toUpperCase()})
        </span>
        <button onclick="handleUserLogout()" class="btn btn-outline-danger btn-sm text-uppercase font-mono" style="font-size:0.75rem;">
          <i class="bi bi-power"></i> Log Out
        </button>
      </div>
      `
    : `
      <div class="d-flex gap-2">
        <a href="login.html" class="btn btn-outline-info btn-sm">Log In</a>
        <a href="register.html" class="btn btn-primary-custom btn-sm">Sign Up</a>
      </div>
      `;

  navbarContainer.innerHTML = `
    <nav class="navbar navbar-expand-lg navbar-dark navbar-custom">
      <div class="container" style="max-width:1200px;">
        <a class="navbar-brand d-flex align-items-center gap-2" href="index.html">
          <i class="bi bi-shield-slash-fill fs-4 text-info"></i> CyberTrace
        </a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#cyberTraceNavbarContent" aria-controls="cyberTraceNavbarContent" aria-expanded="false" aria-label="Toggle navigation">
          <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="cyberTraceNavbarContent">
          <ul class="navbar-nav me-auto mb-2 mb-lg-0 gap-1 ms-lg-4">
            ${navLinks}
          </ul>
          ${authSection}
        </div>
      </div>
    </nav>
  `;
}

function isActiveLink(filename) {
  return window.location.pathname.endsWith(filename);
}

function handleUserLogout() {
  removeToken();
  showToast("Logged out successfully.", "success");
  setTimeout(() => {
    window.location.href = "index.html";
  }, 1000);
}

// Global Toast System
let toastContainer = null;
function showToast(message, type = "info") {
  if (!toastContainer) {
    toastContainer = document.createElement("div");
    toastContainer.className = "toast-container-custom";
    document.body.appendChild(toastContainer);
  }

  const tEl = document.createElement("div");
  tEl.className = `alert alert-${type} shadow-lg py-2.5 px-4 rounded mb-2 border border-secondary border-opacity-20 d-flex align-items-center gap-2 font-mono small`;
  tEl.style.minWidth = "300px";
  tEl.style.boxShadow = "0 8px 32px rgba(0,0,0,0.5)";
  
  let icon = '<i class="bi bi-info-circle-fill"></i>';
  if (type === "success") icon = '<i class="bi bi-check-circle-fill text-success"></i>';
  if (type === "danger") icon = '<i class="bi bi-exclamation-triangle-fill text-danger"></i>';
  if (type === "warning") icon = '<i class="bi bi-exclamation-circle-fill text-warning"></i>';

  tEl.innerHTML = `${icon} <div class="flex-grow-1">${message}</div>`;
  toastContainer.appendChild(tEl);

  setTimeout(() => {
    tEl.style.opacity = "0";
    tEl.style.transition = "opacity 0.5s ease";
    setTimeout(() => {
      tEl.remove();
    }, 500);
  }, 4000);
}
