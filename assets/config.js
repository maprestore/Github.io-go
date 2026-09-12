(function configureLogiSwift() {
    const productionApi = 'https://github-io-go-0l18.onrender.com/api';
    const configured = typeof window.CONSIGNMENT_API_BASE === 'string'
        ? window.CONSIGNMENT_API_BASE.trim()
        : '';

    window.CONSIGNMENT_CONFIG = Object.freeze({
        apiBase: (configured || productionApi).replace(/\/+$/, '')
    });
})();
