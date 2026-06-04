package oauth

import (
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/handler/pkce"
)

// Compile-time guarantees that our storage satisfies every fosite storage
// interface the composed provider relies on. A mismatch fails the build rather
// than panicking at request time.
var (
	_ fosite.ClientManager               = (*storage)(nil)
	_ oauth2.CoreStorage                 = (*storage)(nil)
	_ oauth2.TokenRevocationStorage      = (*storage)(nil)
	_ pkce.PKCERequestStorage            = (*storage)(nil)
	_ openid.OpenIDConnectRequestStorage = (*storage)(nil)
)
