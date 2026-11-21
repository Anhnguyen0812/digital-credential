// Shared HTTP feedback for the three portals.
const portalBusyButtons = new WeakMap();
window.portalRequest = async function(path, options = {}) {
  const {busyButton, timeoutMs = 15000, ...requestOptions} = options;
  const method = requestOptions.method || 'GET';
  const active = document.activeElement;
  const button = busyButton || (method !== 'GET' &&
    (active?.closest('button') || active?.closest('form')?.querySelector('button[type="submit"]')));
  let buttonState;
  if(button) {
    buttonState = portalBusyButtons.get(button);
    if(!buttonState) {
      buttonState = {disabled: button.disabled, label: button.textContent, count: 0};
      portalBusyButtons.set(button, buttonState);
    }
    buttonState.count++;
    button.disabled = true;
    button.setAttribute('aria-busy', 'true');
    button.textContent = 'Đang xử lý…';
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(path, {
      ...requestOptions, credentials: 'same-origin', signal: controller.signal,
      headers: {'Content-Type': 'application/json', ...requestOptions.headers},
      body: requestOptions.body && typeof requestOptions.body !== 'string'
        ? JSON.stringify(requestOptions.body) : requestOptions.body
    });
    const data = await response.json();
    document.getElementById('connectionNotice')?.remove();
    if(response.status >= 500) window.toast?.(data.error || 'Máy chủ đang gặp lỗi. Vui lòng thử lại.', 'err');
    if(response.status === 401 && !path.endsWith('/auth/login')) {
      const app = document.getElementById('appView');
      if(app?.style.display !== 'none') {
        window.dispatchEvent(new Event('portal-session-expired'));
        document.getElementById('loginView').style.display = 'flex';
        app.style.display = 'none';
        window.toast?.('Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại.', 'err');
      }
    }
    return {ok: response.ok, status: response.status, data};
  } catch(error) {
    const message = error.name === 'AbortError'
      ? 'Yêu cầu quá thời gian chờ. Hãy kiểm tra kết quả trước khi thử lại.'
      : 'Không kết nối được máy chủ. Kiểm tra kết nối rồi thử lại.';
    let notice = document.getElementById('connectionNotice');
    if(!notice) {
      notice = document.createElement('div');
      notice.id = 'connectionNotice';
      notice.className = 'connection-notice';
      notice.setAttribute('role', 'alert');
      const text = document.createElement('span');
      const retry = document.createElement('button');
      retry.className = 'btn-secondary btn-sm';
      retry.textContent = 'Tải lại trang';
      retry.onclick = () => location.reload();
      notice.append(text, retry);
      document.querySelector('.portal-topbar').after(notice);
    }
    notice.firstElementChild.textContent = message;
    return {ok: false, status: 0, data: {error: message, code: 'CONNECTION_ERROR'}};
  } finally {
    clearTimeout(timeout);
    if(button) {
      buttonState.count--;
      if(buttonState.count === 0) {
        button.disabled = buttonState.disabled;
        button.textContent = buttonState.label;
        button.removeAttribute('aria-busy');
        portalBusyButtons.delete(button);
      }
    }
  }
};
