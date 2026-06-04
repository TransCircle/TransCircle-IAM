package api

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/transcircle/iam/internal/audit"
	"github.com/transcircle/iam/internal/httpx"
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
	SkipConsent            bool       `json:"skip_consent"`
}

func (cr clientReq) toParams() oauth.CreateParams {
	return oauth.CreateParams{
		ClientName: cr.ClientName, AppID: cr.AppID, Public: cr.Public,
		RedirectURIs: cr.RedirectURIs, PostLogoutRedirectURIs: cr.PostLogoutRedirectURIs,
		GrantTypes: cr.GrantTypes, ResponseTypes: cr.ResponseTypes, AllowedScopes: cr.AllowedScopes,
		AllowedAppKeys: cr.AllowedAppKeys, SkipConsent: cr.SkipConsent,
	}
}

func (h *Handlers) createClient(w http.ResponseWriter, r *http.Request) error {
	var req clientReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	if req.ClientName == "" {
		return httpx.ErrBadRequest.WithDetail("名称必填")
	}
	ctx := r.Context()
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
	httpx.JSON(w, r, http.StatusCreated, map[string]any{"client": client, "client_secret": secret})
	return nil
}

func (h *Handlers) updateClient(w http.ResponseWriter, r *http.Request) error {
	clientID := chi.URLParam(r, "clientID")
	var req clientReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	ctx := r.Context()
	err := h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := h.Clients.Update(ctx, tx, clientID, req.toParams()); err != nil {
			return err
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.client.update", TargetType: "client", TargetID: clientID})
	})
	if err != nil {
		return err
	}
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
			return httpx.ErrBadRequest.WithDetail(err.Error())
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
