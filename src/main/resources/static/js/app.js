// SMART FHIR Client — minimal client-side JS
// No framework — vanilla only. The server does the heavy lifting.

(function () {
  'use strict';

  // ── Token expiry countdown ───────────────────────────────────────────
  // The server embeds tokenExpiresAt as a data attribute on <body>.
  // We display a warning 5 minutes before expiry and refresh the page
  // when the token actually expires (the server will return 401 anyway).
  const expiresAtStr = document.body.dataset.tokenExpiresAt;
  if (expiresAtStr) {
    const expiresAt = new Date(expiresAtStr).getTime();

    function updateCountdown() {
      const now = Date.now();
      const msLeft = expiresAt - now;

      if (msLeft <= 0) {
        // Token expired — reload so the server returns 401 and the user sees
        // a clear "session expired" message rather than stale data.
        window.location.reload();
        return;
      }

      const minLeft = Math.floor(msLeft / 60000);
      const secLeft = Math.floor((msLeft % 60000) / 1000);

      // Show a warning banner 5 minutes before expiry
      if (minLeft < 5) {
        showExpiryWarning(minLeft, secLeft);
      }
    }

    setInterval(updateCountdown, 10000); // check every 10s
    updateCountdown();
  }

  function showExpiryWarning(min, sec) {
    let banner = document.getElementById('expiry-warning');
    if (!banner) {
      banner = document.createElement('div');
      banner.id = 'expiry-warning';
      banner.style.cssText = [
        'position:fixed;bottom:1rem;right:1rem;z-index:9999',
        'background:#FEF2F2;border:1px solid #FECACA;color:#DC2626',
        'padding:.75rem 1rem;border-radius:8px;font-size:13px',
        'font-weight:500;box-shadow:0 4px 6px rgba(0,0,0,.1)',
        'display:flex;align-items:center;gap:8px',
      ].join(';');
      document.body.appendChild(banner);
    }
    banner.innerHTML = '⏰ Session expires in '
      + (min > 0 ? min + 'm ' : '') + sec + 's — save your work.';
  }

  // ── Table row highlight ──────────────────────────────────────────────
  // Highlight the row the user is hovering — already handled by CSS :hover,
  // but this adds a subtle click animation for touch devices.
  document.querySelectorAll('.data-table tr[data-href]').forEach(row => {
    row.style.cursor = 'pointer';
    row.addEventListener('click', () => {
      window.location.href = row.dataset.href;
    });
  });

})();
