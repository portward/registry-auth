package jwt

import (
	"context"
	"testing"
	"time"

	"github.com/docker/libtrust"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/portward/registry-auth/auth"
)

type idGeneratorStub struct {
	id string
}

func (g idGeneratorStub) GenerateID() (string, error) {
	return g.id, nil
}

func TestAccessTokenIssuer_IssueAccessToken(t *testing.T) {
	signingKey, err := libtrust.LoadKeyFile("testdata/private.pem")
	require.NoError(t, err)

	const (
		id         = "vb86v87g87g87g87bb897vcw2367fv723vc8236"
		issuer     = "issuer.example.com"
		service    = "service.example.com"
		expiration = 15 * time.Minute
	)

	now := time.UnixMicro(1257894000000)
	idGenerator := idGeneratorStub{id}
	clock := clockwork.NewFakeClockAt(now)

	tokenIssuer := NewAccessTokenIssuer(issuer, signingKey, expiration, WithClock(clock), WithIDGenerator(idGenerator))

	subject := subjectStub{
		id: "id",
	}

	scopes := []auth.Scope{
		{
			Resource: auth.Resource{
				Type: "repository",
				Name: "path/to/repo",
			},
			Actions: []string{"pull", "push"},
		},
	}

	token, err := tokenIssuer.IssueAccessToken(context.Background(), service, subject, scopes)
	require.NoError(t, err)

	expected := auth.AccessToken{
		Payload:   "eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImtpZCI6IjdCVE06NllVRDpYSE00OjRNWUY6Qk1RWTo2N05YOkFTWVE6VVVBRjo2N1FaOlA3SjY6SktJMjpaT0FBIiwia3R5IjoiUlNBIiwibiI6Ind0bDROcC1YM3Z0cUotZU1oaXc5SWhkRzkyclR5Ukg1c05QVmZsZmZGUHlvZnMyLWtJT0R2bVlOWmFwckRMNHlBU2lvR2k2SkFHamlIcVV5d1JyMUtmTGhsX3RpWGt3YndNalBkZmxwUURuMXpjTC1uWjdkRU1VZVU4WTN0ekN3TVg2bHBVLVd2MDFmNERHNk85eFAzQXJnN0lCNVM0ZmdTXzhCTE5tREhZaUZmSFlzSHBhMFI2Wk10UV9VcG9yTXJDcDlnR0VaYkswbkVnTnZyWTFCel9ZRUtRUFZZNUxRTTdfZFoxMWcwS3hibGpBa3hmZnVoY0RUNE9rN1FTdnRGWHVTbFBINktNbDdtYjRJaERkaHRzbHU3YnExV3lkdmEwSmtwajQ5QlFuci13VkJHZU5ROFJHSUhXaGJqWE5uNzVMdF9rNGZCOUxnRGViQmRTNkpiSUlEUUNheHU3dmpnUE9EN2tDcUVxRVFYR0VjMHdzNlZ3MlAzLUF0NXhzNHJnVFhNYVU4NmdpVXExVXFGOE0zWFRDcEtXLTgyaHN6NjRIZk1IVUNpbVpiX2pnM205N3A2Wm9oU0tSaHlSWjRyLW05U0hzMnVBSXJkZmYzOGhLcEVGUWJCTWs1SkN5a05sTDViQWxNbjItZmpQZHdjMV9TWi1Db3hIQjlrVlhoZTRIRTdYU185bXJhTUdwZlVEOGY0OTBwZFZOVkd2NHVyenJSMDMxZ3RRbzg4SWRsb2ZkRTBGOFpBQWp6a3dUS1c3WGRpMzJXTUdRNlE1b3F6amxfc1V2OUV4Qy1pc2R6MklHX3RHU184M0gxN1N0RERsd0Jpa21iMEYxQUZNM2s2RzB1SzhzVFg5RElhS1pEVXFJU1BrM1ZaV1JCR0s1N3l1MEk5S3haeFRVIn0sInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3N1ZXIuZXhhbXBsZS5jb20iLCJzdWIiOiJpZCIsImF1ZCI6WyJzZXJ2aWNlLmV4YW1wbGUuY29tIl0sImV4cCI6MTI1ODc5NCwibmJmIjoxMjU3ODk0LCJpYXQiOjEyNTc4OTQsImp0aSI6InZiODZ2ODdnODdnODdnODdiYjg5N3ZjdzIzNjdmdjcyM3ZjODIzNiIsImFjY2VzcyI6W3sidHlwZSI6InJlcG9zaXRvcnkiLCJjbGFzcyI6IiIsIm5hbWUiOiJwYXRoL3RvL3JlcG8iLCJhY3Rpb25zIjpbInB1bGwiLCJwdXNoIl19XX0.Mm48dysRPmHah3R3tYJ6pZ9aowbCYmeNiLCzlGogAQm_pQ2oiAwMUDIK9xSKFw0nS7FB2ljoMVRAyJbNvpTc7FZFCI6ZksS3j1c_GUDlADmapuQRz39Hf_7RexN5KGO0d4f-aLlKC7z-Q1gyxnjSukjnztFLzRsYwA2U1uT-BzuBy5TNEtEaqiehCMSuQWKJnm9bBgxI3NFGQplZofKugf9sUFiuhldGpY1XNk1Guwp9inQsVm8sTHlEq_1kIx8OlIm9afkBEe2etxl7fE0LM3rhRj6m9gxEgijMYvHQRJIwrSW1_CtYNPAAAnF3OsHucuXXW2K4ItKAkqDZJetIePtv0T3IiA-lD0v0Ou5qM96IDV4ZFlp8xAjIr0fJ97VCOwpO9Z03ovi0V3hEcKt8HKwmdsHgm7k7Kr0ROiyldVoPVuH1BqoCKPeDxIlHqobcvCdCA3erqr5kYM0eK3l1cSIn58d5udrtYuUwaF-yU98qSRlbOU5bgkASESWycyXbss1z6BsshQiwFQ406fUBCVDeYM0evMNXov6coyv1DnLl7eU6vOQSIi5YfJ23yPVsNF-CxJpSZjRFr6MuY2qhoQJ_C-EKmFzD1yirEFndoLhFqFFkxLXoY6W5EA2LR8dCd7JO0lpFAHDd6Uqkcf380BltzG_qpdkCHlaZYIQxerw",
		ExpiresIn: expiration,
		IssuedAt:  now,
	}

	assert.Equal(t, expected, token)
}
