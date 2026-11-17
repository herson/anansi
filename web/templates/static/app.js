// Dashboard behaviour. Loaded from /static so the page can run under
// a CSP without 'unsafe-inline' (ADR-0002). Requests are same-origin, so
// the browser attaches the session cookie (ADR-0001).
(function () {
    const form = document.getElementById('scanForm');
    if (!form) return;

    const target = document.getElementById('targetInput');
    const cve = document.getElementById('cveCheck');
    const button = document.getElementById('scanBtn');
    const error = document.getElementById('scanError');
    const progress = document.getElementById('progressContainer');
    const bar = document.getElementById('progressBar');
    const pct = document.getElementById('progressPct');
    const message = document.getElementById('progressMsg');

    function showError(text) {
        error.textContent = text;
        error.hidden = false;
    }

    function showProgress(value, text) {
        progress.hidden = false;
        bar.value = value;
        pct.textContent = value + '%';
        message.textContent = text;
    }

    function setBusy(busy) {
        button.disabled = busy;
        if (!busy) progress.hidden = true;
    }

    function listenProgress() {
        const events = new EventSource('/api/progress');
        events.onmessage = function (e) {
            const data = JSON.parse(e.data);
            showProgress(data.pct, data.message);
            if (data.done) {
                events.close();
                window.location.reload();
            }
        };
        events.onerror = function () {
            events.close();
            window.location.reload();
        };
    }

    form.addEventListener('submit', async function (e) {
        e.preventDefault();
        error.hidden = true;
        const value = target.value.trim();
        if (!value) {
            showError('Enter a target IP address or CIDR range.');
            target.focus();
            return;
        }

        setBusy(true);
        showProgress(0, 'Starting...');
        try {
            const params = new URLSearchParams({target: value, cve: cve.checked});
            const res = await fetch('/scan?' + params, {method: 'POST'});
            if (res.status === 401) {
                window.location.assign('/login');
                return;
            }
            const data = await res.json();
            if (data.status === 'success') {
                listenProgress();
            } else {
                showError(data.message || data.detail || 'The scan could not be started.');
                setBusy(false);
            }
        } catch (err) {
            showError('Failed to start the scan.');
            setBusy(false);
        }
    });
})();
