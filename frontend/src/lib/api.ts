import axios, { type AxiosError, type InternalAxiosRequestConfig } from "axios";
import { getCookie } from "./utils";
import { requestStepUp } from "./stepup";

export const api = axios.create({ baseURL: "/", withCredentials: true });

// Attach the CSRF token (double-submit) on unsafe requests.
api.interceptors.request.use((config) => {
  const method = (config.method || "get").toLowerCase();
  if (!["get", "head", "options"].includes(method)) {
    const token = getCookie("__Host-tc_csrf") || getCookie("tc_csrf");
    if (token) config.headers.set("X-CSRF-Token", token);
  }
  return config;
});

// When the backend asks for step-up (403 step_up_required), open the MFA dialog,
// then transparently retry the original request once.
api.interceptors.response.use(
  (res) => res,
  async (error: AxiosError<ProblemError>) => {
    const cfg = error.config as (InternalAxiosRequestConfig & { _stepUpRetried?: boolean }) | undefined;
    const code = error.response?.data?.code;
    const isStepUpEndpoint = cfg?.url?.includes("/auth/step-up");
    if (error.response?.status === 403 && code === "step_up_required" && cfg && !cfg._stepUpRetried && !isStepUpEndpoint) {
      cfg._stepUpRetried = true;
      await requestStepUp(); // resolves once the user re-verifies MFA
      return api(cfg); // retry
    }
    return Promise.reject(error);
  }
);

export interface ProblemError {
  code: string;
  title: string;
  detail?: string;
  fields?: Record<string, unknown>;
}

export function problemFrom(err: unknown): ProblemError {
  const ax = err as AxiosError<ProblemError>;
  if (ax?.response?.data?.code) return ax.response.data;
  return { code: "network_error", title: "网络错误，请稍后重试" };
}

export function errorMessage(err: unknown): string {
  const p = problemFrom(err);
  return p.detail || p.title;
}
