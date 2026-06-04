import axios, { type AxiosError } from "axios";
import { getCookie } from "./utils";

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
