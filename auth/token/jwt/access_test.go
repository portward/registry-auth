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
		id: auth.SubjectIDFromString("id"),
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
		Payload:   "eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImtpZCI6IjdCVE06NllVRDpYSE00OjRNWUY6Qk1RWTo2N05YOkFTWVE6VVVBRjo2N1FaOlA3SjY6SktJMjpaT0FBIiwia3R5IjoiUlNBIiwibiI6Ind0bDROcC1YM3Z0cUotZU1oaXc5SWhkRzkyclR5Ukg1c05QVmZsZmZGUHlvZnMyLWtJT0R2bVlOWmFwckRMNHlBU2lvR2k2SkFHamlIcVV5d1JyMUtmTGhsX3RpWGt3YndNalBkZmxwUURuMXpjTC1uWjdkRU1VZVU4WTN0ekN3TVg2bHBVLVd2MDFmNERHNk85eFAzQXJnN0lCNVM0ZmdTXzhCTE5tREhZaUZmSFlzSHBhMFI2Wk10UV9VcG9yTXJDcDlnR0VaYkswbkVnTnZyWTFCel9ZRUtRUFZZNUxRTTdfZFoxMWcwS3hibGpBa3hmZnVoY0RUNE9rN1FTdnRGWHVTbFBINktNbDdtYjRJaERkaHRzbHU3YnExV3lkdmEwSmtwajQ5QlFuci13VkJHZU5ROFJHSUhXaGJqWE5uNzVMdF9rNGZCOUxnRGViQmRTNkpiSUlEUUNheHU3dmpnUE9EN2tDcUVxRVFYR0VjMHdzNlZ3MlAzLUF0NXhzNHJnVFhNYVU4NmdpVXExVXFGOE0zWFRDcEtXLTgyaHN6NjRIZk1IVUNpbVpiX2pnM205N3A2Wm9oU0tSaHlSWjRyLW05U0hzMnVBSXJkZmYzOGhLcEVGUWJCTWs1SkN5a05sTDViQWxNbjItZmpQZHdjMV9TWi1Db3hIQjlrVlhoZTRIRTdYU185bXJhTUdwZlVEOGY0OTBwZFZOVkd2NHVyenJSMDMxZ3RRbzg4SWRsb2ZkRTBGOFpBQWp6a3dUS1c3WGRpMzJXTUdRNlE1b3F6amxfc1V2OUV4Qy1pc2R6MklHX3RHU184M0gxN1N0RERsd0Jpa21iMEYxQUZNM2s2RzB1SzhzVFg5RElhS1pEVXFJU1BrM1ZaV1JCR0s1N3l1MEk5S3haeFRVIn0sInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3N1ZXIuZXhhbXBsZS5jb20iLCJzdWIiOiJpZCIsImF1ZCI6WyJzZXJ2aWNlLmV4YW1wbGUuY29tIl0sImV4cCI6MTI1ODc5NCwibmJmIjoxMjU3ODk0LCJpYXQiOjEyNTc4OTQsImp0aSI6InZiODZ2ODdnODdnODdnODdiYjg5N3ZjdzIzNjdmdjcyM3ZjODIzNiIsImFjY2VzcyI6W3sidHlwZSI6InJlcG9zaXRvcnkiLCJuYW1lIjoicGF0aC90by9yZXBvIiwiYWN0aW9ucyI6WyJwdWxsIiwicHVzaCJdfV19.dkml_iXfUGUQ5-yljJz8kZvFJM5drmMXruNiXTR9HP--wLisyYVeB_ltwOV0KKrkLWUB6BVOnnSjrctOuu0JGKXXlouRDVh3T0zafUSJHFPGkXPBfF_4p2qIH61vqfH7HyYG52z5X6dxkCcclfg_jR8Afz35rdHVW-D9b_bu4Q76lwEP-2zJ82IJn9diHcKUJzImqJJzL_bmnsdDkW0W1LPXOigQrp6-fzUuCQCxGh_Q1IODTJc6hf000W0TTT8iz14fQUGt6F1k4HShpEVTbS5Iymf1D1rAVHJ4uibsT0knVncpwG65Exoaj36m9AIQu9ctDF_jFZF-pRhQivWmc2BQLw1w_IKbzb5DnldYwRxPQrnOODQleu0c8H8feMBQh3dwA2S0MzjPtSXRz1w8tTVU6OJcArK0sSWY5zZ5ZlOAax9MthE7MXXpd-kWJoQ5O8KWop0bF4x5iazm23NU9_Cu8m-YU0M565GA-g-prhS_JaFl0Hp5vGQ5hHlhSLO4LJ2jyTCoaIzgE2tTlrOU3Lbo74PA6MtXIzk23cX6CkrlnthKZaUiNGJYjMLU7rRGIJr54Rtr4RkolXTT8uZ56Tjqp4k_5NCuxQL7RUicRhj735PYRHaPs3_2Xvzx8S83UGt3lzCpouQBZDzJqxT1PN-GfYHeCP8PUfhg2nKS1RM",
		ExpiresIn: expiration,
		IssuedAt:  now,
	}

	assert.Equal(t, expected, token)
}
