package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/gorilla/schema"
)

// Set a Decoder instance as a package global, because it caches
// meta-data about structs, and an instance can be shared safely.
var decoder = schema.NewDecoder()

func init() {
	decoder.IgnoreUnknownKeys(true)
}

// AuthorizationServer implements the [Docker Registry v2 authentication] specification.
//
// [Docker Registry v2 authentication]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/index.md
type AuthorizationServer struct {
	Service AuthorizationService

	ErrorHandler ErrorHandler
}

func httpHandleError(err error, w http.ResponseWriter) {
	if errors.Is(err, ErrAuthenticationFailed) {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)

		return
	}

	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}

func (s AuthorizationServer) handleError(err error) {
	if s.ErrorHandler == nil {
		return
	}

	s.ErrorHandler.Handle(err)
}

// TokenHandler implements the [Docker Registry v2 authentication] specification.
//
// [Docker Registry v2 authentication]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/token.md
func (s AuthorizationServer) TokenHandler(w http.ResponseWriter, r *http.Request) {
	request, err := decodeTokenRequest(r)
	if err != nil {
		s.handleError(fmt.Errorf("decoding token request: %w", err))
		httpHandleError(err, w)

		return
	}

	response, err := s.Service.TokenHandler(r.Context(), request)
	if err != nil {
		httpHandleError(err, w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		s.handleError(fmt.Errorf("encoding token response: %w", err))
	}
}

// TODO: error handling 400
func decodeTokenRequest(r *http.Request) (TokenRequest, error) {
	var rawRequest rawTokenRequest

	err := decoder.Decode(&rawRequest, r.URL.Query())
	if err != nil {
		return TokenRequest{}, err
	}

	scopes, err := ParseScopes(rawRequest.Scopes)
	if err != nil {
		return TokenRequest{}, err
	}

	request := TokenRequest{
		Service:  rawRequest.Service,
		ClientID: rawRequest.ClientID,
		Offline:  rawRequest.Offline,
		Scopes:   scopes,
	}

	username, password, ok := r.BasicAuth()
	request.Anonymous = !ok
	request.Username = username
	request.Password = password

	return request, nil
}

type rawTokenRequest struct {
	Service  string   `schema:"service"`
	ClientID string   `schema:"client_id"`
	Offline  bool     `schema:"offline_token"`
	Scopes   []string `schema:"scope"`
}

// OAuth2Handler implements the [Docker Registry v2 OAuth2 authentication] specification.
//
// [Docker Registry v2 OAuth2 authentication]: https://github.com/distribution/distribution/blob/main/docs/spec/auth/oauth.md
func (s AuthorizationServer) OAuth2Handler(w http.ResponseWriter, r *http.Request) {
	request, err := decodeOAuth2Request(r)
	if err != nil {
		s.handleError(fmt.Errorf("decoding oauth2 token request: %w", err))
		httpHandleError(err, w)

		return
	}

	response, err := s.Service.OAuth2Handler(r.Context(), request)
	if err != nil {
		httpHandleError(err, w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		s.handleError(fmt.Errorf("encoding oauth2 token response: %w", err))
	}
}

// TODO: error handling 400
func decodeOAuth2Request(r *http.Request) (OAuth2Request, error) {
	err := r.ParseForm()
	if err != nil {
		return OAuth2Request{}, err
	}

	var rawRequest rawOAuth2Request

	err = decoder.Decode(&rawRequest, r.PostForm)
	if err != nil {
		return OAuth2Request{}, err
	}

	scopes, err := ParseScopes(rawRequest.Scopes)
	if err != nil {
		return OAuth2Request{}, err
	}

	request := OAuth2Request{
		GrantType:    rawRequest.GrantType,
		Service:      rawRequest.Service,
		ClientID:     rawRequest.ClientID,
		AccessType:   rawRequest.AccessType,
		Scopes:       scopes,
		Username:     rawRequest.Username,
		Password:     rawRequest.Password,
		RefreshToken: rawRequest.RefreshToken,
	}

	return request, nil
}

type rawOAuth2Request struct {
	GrantType string `schema:"grant_type"`

	Service    string   `schema:"service"`
	ClientID   string   `schema:"client_id"`
	AccessType string   `schema:"access_type"`
	Scopes     []string `schema:"scope"`

	Username     string `schema:"username"`
	Password     string `schema:"password"`
	RefreshToken string `schema:"refresh_token"`
}
