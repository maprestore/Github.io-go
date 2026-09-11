(function configureLogiSwift() {
    const productionApi = 'https://github-io-go-0l18.onrender.com/api';
    const configured = typeof window.LOGISWIFT_API_BASE === 'string'
        ? window.LOGISWIFT_API_BASE.trim()
        : '';

    window.LOGISWIFT_CONFIG = Object.freeze({
        apiBase: (configured || productionApi).replace(/\/+$/, '')
    });
})();
