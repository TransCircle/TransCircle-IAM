package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/transcircle/iam/internal/audit"
	"github.com/transcircle/iam/internal/httpx"
	"github.com/transcircle/iam/internal/logging"
	"github.com/transcircle/iam/internal/oauth"
)

func (h *Handlers) listClients(w http.ResponseWriter, r *http.Request) error {
	list, err := h.Clients.List(r.Context())
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{"clients": list})
	return nil
}

func (h *Handlers) getClient(w http.ResponseWriter, r *http.Request) error {
	clientID := chi.URLParam(r, "clientID")
	c, err := h.Clients.Get(r.Context(), h.Store.Pool, clientID)
	if errors.Is(err, oauth.ErrNotFound) {
		return httpx.ErrNotFound.WithDetail("客户端不存在")
	}
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{"client": c})
	return nil
}

type clientReq struct {
	ClientName             string     `json:"client_name"`
	AppID                  *uuid.UUID `json:"app_id"`
	Public                 bool       `json:"public"`
	RedirectURIs           []string   `json:"redirect_uris"`
	PostLogoutRedirectURIs []string   `json:"post_logout_redirect_uris"`
	GrantTypes             []string   `json:"grant_types"`
	ResponseTypes          []string   `json:"response_types"`
	AllowedScopes          []string   `json:"allowed_scopes"`
	AllowedAppKeys         []string   `json:"allowed_app_keys"`
	Audience               []string   `json:"audience"`
	SkipConsent            bool       `json:"skip_consent"`
	// Login allowlist (empty across all three = unrestricted). OR semantics.
	LoginAllowedUserIDs   []uuid.UUID `json:"login_allowed_user_ids"`
	LoginAllowedGroupKeys []string    `json:"login_allowed_group_keys"`
	LoginRequiredPerms    []string    `json:"login_required_perms"`
	// Pointers so an omitted field defaults to true at creation (the secure
	// default) while an explicit false on edit is honoured.
	PKCERequired *bool `json:"pkce_required"`
	Active       *bool `json:"active"`
}

func boolOrTrue(v *bool) bool { return v == nil || *v }

func (cr clientReq) toParams() oauth.CreateParams {
	return oauth.CreateParams{
		ClientName: cr.ClientName, AppID: cr.AppID, Public: cr.Public,
		RedirectURIs: cr.RedirectURIs, PostLogoutRedirectURIs: cr.PostLogoutRedirectURIs,
		GrantTypes: cr.GrantTypes, ResponseTypes: cr.ResponseTypes, AllowedScopes: cr.AllowedScopes,
		AllowedAppKeys: cr.AllowedAppKeys, Audience: cr.Audience, SkipConsent: cr.SkipConsent,
		PKCERequired: boolOrTrue(cr.PKCERequired), Active: boolOrTrue(cr.Active),
		LoginAllowedUserIDs:   cr.LoginAllowedUserIDs,
		LoginAllowedGroupKeys: cr.LoginAllowedGroupKeys,
		LoginRequiredPerms:    cr.LoginRequiredPerms,
	}
}

// requireSuperAdminForSkipConsent enforces the contract that only a super-admin
// may register or promote a first-party "skip consent" client (silent auth-code
// issuance). A plain iam.clients.write holder must not be able to mint a client
// that bypasses the user consent screen. See iam-main-api.md §5.1 / §8.
func (h *Handlers) requireSuperAdminForSkipConsent(ctx context.Context, r *http.Request, skipConsent bool) error {
	if !skipConsent {
		return nil
	}
	super, err := h.isSuperAdmin(ctx, actorID(r))
	if err != nil {
		return err
	}
	if !super {
		return httpx.ErrForbidden.WithDetail("仅超级管理员可将客户端标记为可信(skip_consent)")
	}
	return nil
}

// validateRedirectURIs 在注册期就拒绝明显非法的 redirect_uri：必须是绝对 URI 且不含
// 片段(#)。不限制 scheme（https / http-localhost / 原生自定义 scheme 均可），授权时另由
// fosite 精确匹配兜底。
func validateRedirectURIs(uris []string) error {
	for _, raw := range uris {
		u, err := url.Parse(raw)
		if err != nil || !u.IsAbs() {
			return httpx.ErrBadRequest.WithDetail("redirect_uri 必须是绝对 URI：" + raw)
		}
		if u.Fragment != "" {
			return httpx.ErrBadRequest.WithDetail("redirect_uri 不得包含片段(#)：" + raw)
		}
	}
	return nil
}

func (h *Handlers) createClient(w http.ResponseWriter, r *http.Request) error {
	var req clientReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	if req.ClientName == "" {
		return httpx.ErrBadRequest.WithDetail("名称必填")
	}
	if err := validateRedirectURIs(req.RedirectURIs); err != nil {
		return err
	}
	ctx := r.Context()
	if err := h.requireSuperAdminForSkipConsent(ctx, r, req.SkipConsent); err != nil {
		return err
	}
	var client *oauth.Client
	var secret string
	err := h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		c, s, err := h.Clients.Create(ctx, tx, req.toParams())
		if err != nil {
			return err
		}
		client, secret = c, s
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.client.create", TargetType: "client", TargetID: c.ClientID, TargetLabel: c.ClientName})
	})
	if err != nil {
		return err
	}
	// Client lifecycle also goes to the operational log (audit_log is DB-only),
	// so "no such client" warnings at /oauth2/auth can be correlated in one place.
	logging.From(ctx).Info("oauth client created", "client_id", client.ClientID, "client_name", client.ClientName)
	httpx.JSON(w, r, http.StatusCreated, map[string]any{"client": client, "client_secret": secret})
	return nil
}

func (h *Handlers) updateClient(w http.ResponseWriter, r *http.Request) error {
	clientID := chi.URLParam(r, "clientID")
	var req clientReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	if err := validateRedirectURIs(req.RedirectURIs); err != nil {
		return err
	}
	ctx := r.Context()
	if err := h.requireSuperAdminForSkipConsent(ctx, r, req.SkipConsent); err != nil {
		return err
	}
	err := h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := h.Clients.Update(ctx, tx, clientID, req.toParams()); err != nil {
			return err
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.client.update", TargetType: "client", TargetID: clientID})
	})
	if err != nil {
		return err
	}
	logging.From(ctx).Info("oauth client updated", "client_id", clientID)
	httpx.NoContent(w)
	return nil
}

func (h *Handlers) deleteClient(w http.ResponseWriter, r *http.Request) error {
	clientID := chi.URLParam(r, "clientID")
	ctx := r.Context()
	err := h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := h.Clients.Delete(ctx, tx, clientID); err != nil {
			return err
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.client.delete", TargetType: "client", TargetID: clientID})
	})
	if err != nil {
		return err
	}
	logging.From(ctx).Info("oauth client deleted", "client_id", clientID)
	httpx.NoContent(w)
	return nil
}

func (h *Handlers) rotateClientSecret(w http.ResponseWriter, r *http.Request) error {
	clientID := chi.URLParam(r, "clientID")
	ctx := r.Context()
	var secret string
	err := h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		s, err := h.Clients.RotateSecret(ctx, tx, clientID)
		if err != nil {
			return err
		}
		secret = s
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.client.rotate_secret", TargetType: "client", TargetID: clientID})
	})
	if err != nil {
		return err
	}
	logging.From(ctx).Info("oauth client secret rotated", "client_id", clientID)
	httpx.JSON(w, r, http.StatusOK, map[string]string{"client_secret": secret})
	return nil
}

func (h *Handlers) revealClientSecret(w http.ResponseWriter, r *http.Request) error {
	clientID := chi.URLParam(r, "clientID")
	ctx := r.Context()
	var secret string
	err := h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		s, err := h.Clients.RevealSecret(ctx, tx, clientID)
		if err != nil {
			if errors.Is(err, oauth.ErrNotFound) {
				return httpx.ErrNotFound
			}
			// Most often the one-time secret was already revealed/burned; never
			// echo the raw internal error text to the client.
			return httpx.ErrBadRequest.WithDetail("密钥已不可再次查看，请轮换后重试").WithInternal(err)
		}
		secret = s
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.client.reveal_secret", TargetType: "client", TargetID: clientID})
	})
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusOK, map[string]string{"client_secret": secret})
	return nil
}
