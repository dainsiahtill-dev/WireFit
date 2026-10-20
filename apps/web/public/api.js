class ApiError extends Error {
  constructor(code, message, status) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
  }
}
function createApi() {
  let token = "";
  return { setToken(value) {
    token = value;
  }, async request(path, options = {}) {
    const headers = { "Accept": "application/json", ...options.headers };
    if (options.method && options.method !== "GET") {
      headers["Content-Type"] = "application/json";
      headers["X-Wirefit-Token"] = token;
    }
    const response = await fetch(path, { ...options, headers, credentials: "same-origin", cache: "no-store", body: options.body === void 0 ? void 0 : JSON.stringify(options.body) });
    let payload;
    try {
      payload = await response.json();
    } catch {
      throw new ApiError("INVALID_RESPONSE", "服务返回了无法解析的响应", response.status);
    }
    if (!response.ok || payload.error) throw new ApiError(payload.error?.code ?? "HTTP_ERROR", payload.error?.message ?? `HTTP ${response.status}`, response.status);
    if (!Object.prototype.hasOwnProperty.call(payload, "data")) throw new ApiError("INVALID_RESPONSE", "响应缺少 data 字段", response.status);
    return payload.data;
  } };
}
const enc = (value) => encodeURIComponent(value);
export {
  ApiError,
  createApi,
  enc
};
