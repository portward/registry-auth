package jwt

import (
	"context"
	"testing"
	"time"

	"github.com/docker/libtrust"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefreshTokenIssuer_IssueRefreshToken(t *testing.T) {
	signingKey, err := libtrust.LoadKeyFile("testdata/private.pem")
	require.NoError(t, err)

	const (
		issuer  = "issuer.example.com"
		service = "service.example.com"
	)

	now := time.UnixMicro(1257894000000)
	clock := clockwork.NewFakeClockAt(now)

	tokenIssuer := NewRefreshTokenIssuer(issuer, signingKey, WithClock(clock))

	subject := subjectStub{
		id: "id",
	}

	token, err := tokenIssuer.IssueRefreshToken(context.Background(), service, subject)
	require.NoError(t, err)

	const expected = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3N1ZXIuZXhhbXBsZS5jb20iLCJzdWIiOiJpZCIsImF1ZCI6WyJzZXJ2aWNlLmV4YW1wbGUuY29tIl0sIm5iZiI6MTI1Nzg5NCwiaWF0IjoxMjU3ODk0fQ.I2d8UMclJZMpMG9qs0b8Dun-QQC7CMbfo2a_T4r75sN_1nVgV-DDoT8CbmfV0X1Kpx6hTb8aU35Z5WsFaNjofK3hMUc_LdCt7uk6EQhlJy2NV1UrnOq3b8LAFFWV5Ui_e7sm5Cp4j7-ydlbLIKDAFafSFphvyOKGJP67nw35p7qi5DB316bY-VEVjYNZCjcJqKYlv4HX9JDNsdbruKEXTIidM6b_GKBM2nLn18bx176bw_6RqOc-X-wXY9kjDBnyqLcRxsTLLUqLHOgDYHBSfxo_uFIM8IYwQypmpOIdwaz4MdWa06kUOOgy6FMKYfUk74olPdYjA3DAGQb9CuJuiBOZzGIw6PH59S0WlIfKxDTEm3JDJtLnoTPXsRb1yqfzQWugIkz_lVeZgvJRgK9M7st5Pa4f5d11tRp_xsWCV2-VrPHjguhlrS1p0fs05kDgRBI621Ai9EL2OyaXVuuLJxCrCnuhwDoSjKtGf2RdnT9XHDGFGtf41yBChNK5OBvkY4iQJa8hz76eBd3yNXfUJsUVroFG-MbRfkw_BzjvXIW6_AV3IRB9gJ_qD3AUV4c6cQDDGK7uJWIpiyIWWM5Agb02wXMWIp4tcMPBo5Uype4CVHH6Gz9dH1oryMs_L6AVenbt1eyVHjxq11YY-wpzkiIARYEFAzkwRtFjKmfhq-w"

	assert.Equal(t, expected, token)
}
