import { startRegistration, startAuthentication } from "@simplewebauthn/browser";
import { api } from "./api";

// registerPasskey runs the WebAuthn registration ceremony for the current user.
export async function registerPasskey(name: string): Promise<void> {
  const begin = await api.post("/api/v1/auth/webauthn/register/begin");
  const { options, wa_ticket } = begin.data as { options: unknown; wa_ticket: string };
  const attestation = await startRegistration({ optionsJSON: options as any });
  await api.post(
    `/api/v1/auth/webauthn/register/finish?wt=${encodeURIComponent(wa_ticket)}&name=${encodeURIComponent(name)}`,
    attestation
  );
}

// stepUpPasskey re-verifies the current user's passkey within an active session
// (refreshes the step-up window).
export async function stepUpPasskey(): Promise<void> {
  const begin = await api.post("/api/v1/auth/step-up/webauthn/begin");
  const { options, wa_ticket } = begin.data as { options: unknown; wa_ticket: string };
  const assertion = await startAuthentication({ optionsJSON: options as any });
  await api.post(`/api/v1/auth/step-up/webauthn/finish?wt=${encodeURIComponent(wa_ticket)}`, assertion);
}

// verifyPasskey runs a passkey assertion for the standalone two-factor
// verification flow (the hosted /verify/{id} page) and returns the app redirect.
export async function verifyPasskey(id: string): Promise<{ status: string; redirect_uri: string }> {
  const begin = await api.post(`/api/v1/verify/${encodeURIComponent(id)}/webauthn/begin`);
  const { options, wa_ticket } = begin.data as { options: unknown; wa_ticket: string };
  const assertion = await startAuthentication({ optionsJSON: options as any });
  const finish = await api.post(`/api/v1/verify/${encodeURIComponent(id)}/webauthn/finish?wt=${encodeURIComponent(wa_ticket)}`, assertion);
  return finish.data as { status: string; redirect_uri: string };
}

// loginPasskey runs the assertion ceremony during login for the given ticket.
export async function loginPasskey(ticket: string): Promise<{ required_action: string }> {
  const begin = await api.post("/api/v1/auth/webauthn/login/begin", { ticket });
  const { options, wa_ticket } = begin.data as { options: unknown; wa_ticket: string };
  const assertion = await startAuthentication({ optionsJSON: options as any });
  const finish = await api.post(
    `/api/v1/auth/webauthn/login/finish?lt=${encodeURIComponent(ticket)}&wt=${encodeURIComponent(wa_ticket)}`,
    assertion
  );
  return finish.data as { required_action: string };
}
