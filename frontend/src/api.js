export const API_BASE_URL = (
  import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'
).replace(/\/+$/, '');

export async function apiFetch(path, options = {}) {
  const response = await fetch(`${API_BASE_URL}${path}`, options);
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
