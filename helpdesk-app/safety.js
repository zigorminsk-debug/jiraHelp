'use strict';
function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, char => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[char]));
}
// IDs appear in inline event handlers. HTML escaping alone is NOT sufficient there.
function safeId(value) {
    return /^[A-Za-z0-9_-]+$/.test(String(value)) ? String(value) : '';
}
function cssToken(value) {
    return /^[a-z-]+$/.test(String(value)) ? String(value) : 'unknown';
}
function hasNative(method) {
    return !!window.AndroidBridge && typeof window.AndroidBridge[method] === 'function';
}
function callNative(method, ...args) {
    if (!hasNative(method)) {
        showToast('Jira-синхронизация недоступна: метод ' + method + ' не реализован');
        return undefined;
    }
    return window.AndroidBridge[method](...args);
}
