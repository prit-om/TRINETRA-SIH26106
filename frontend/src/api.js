export const API_BASE_URL = (
  import.meta.env.VITE_API_BASE_URL !== undefined
    ? import.meta.env.VITE_API_BASE_URL
    : ''
).replace(/\/+$/, '');

export function getStoredApiKey() {
  try {
    return localStorage.getItem('trinetra_api_key') || '';
  } catch {
    return '';
  }
}

export function setStoredApiKey(key) {
  try {
    if (key && key.trim()) {
      localStorage.setItem('trinetra_api_key', key.trim());
    } else {
      localStorage.removeItem('trinetra_api_key');
    }
  } catch {
    // Ignore storage errors
  }
}

export async function apiFetch(path, options = {}) {
  const headers = new Headers(options.headers || {});
  const storedKey = getStoredApiKey();
  if (storedKey && !headers.has('x-trinetra-api-key') && !headers.has('Authorization')) {
    headers.set('x-trinetra-api-key', storedKey);
  }
  const opts = { ...options, headers };

  const response = await fetch(`${API_BASE_URL}${path}`, opts);
  if (!response.ok) {
    let detail = '';
    try {
      const data = await response.json();
      detail = data?.detail || data?.message || '';
    } catch {
      // Response was not JSON.
    }
    throw new Error(detail || `Request failed with HTTP ${response.status}`);
  }
  return response;
}
