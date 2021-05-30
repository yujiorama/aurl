package request

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/toqueteos/webbrowser"
)

func receiveAuthCodeFromStdin() (string, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Fprint(os.Stderr, "Enter code: ")
	if code, _, err := reader.ReadLine(); err != nil {
		return "", err
	} else {
		return string(code), nil
	}
}

func receiveTokenFromLocalServerWithSSO(rawURL string, request *AurlExecution, state, nonce string) (*string, error) {

	redirectURI, _ := url.Parse(rawURL)

	if redirectURI.Hostname() != "localhost" {
		return nil, errors.New("not implemented")
	}

	addr := fmt.Sprintf(":%s", redirectURI.Port())
	if l, err := net.Listen("tcp", addr); err != nil {
		fmt.Fprintf(os.Stderr, "error: port[%s] already used", redirectURI.Port())
		return nil, err
	} else {
		l.Close()
	}

	tokenCh := make(chan string)
	errCh := make(chan error)
	defer close(tokenCh)
	defer close(errCh)

	server := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("callback request: %v\n", r)
			if r.URL.Path != redirectURI.Path {
				w.WriteHeader(http.StatusNotFound)
				return
			}

			query := r.URL.Query()
			if _, ok := query["code"]; !ok {
				authzRequestURL, _ := url.Parse(authorizationRequestURL("code", request, rawURL, state, nonce))
				w.Header().Set("Content-Length", "0")
				w.Header().Set("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate")
				w.Header().Set("Pragma", "no-cache")
				w.Header().Set("Expires", "0")
				w.Header().Set("Location", authzRequestURL.String())
				w.WriteHeader(http.StatusFound)
				log.Printf("send redirect: %v\n", authzRequestURL)
				return
			}

			code := query.Get("code")
			w.Header().Set("Content-Type", "text/plain")
			if code == "" {
				errCh <- errors.New("missing code")
				w.WriteHeader(http.StatusBadRequest)
			} else {
				values := url.Values{
					"grant_type":   {"authorization_code"},
					"code":         {code},
					"redirect_uri": {request.Profile.RedirectURI},
				}
				if pkce := request.Profile.PKCE; pkce.Enabled() {
					values.Add("code_verifier", pkce.CodeVerifier)
				}

				if tokenResponse, err := tokenRequest(values, request); err != nil {
					errCh <- errors.New("error token")
					w.WriteHeader(http.StatusBadRequest)
				} else {
					tokenCh <- *tokenResponse
					w.Write([]byte(fmt.Sprintf("tokenResponse: [%s]", *tokenResponse)))
					w.WriteHeader(http.StatusOK)
				}
			}
		}),
	}
	defer server.Shutdown(context.TODO())

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		log.Printf("callback server error: %v\n", err)
		return nil, err
	case tokenResponse := <-tokenCh:
		return &tokenResponse, nil
	}
}

func receiveAuthCodeFromLocalServer(rawURL string) (string, error) {

	redirectURI, _ := url.Parse(rawURL)

	if redirectURI.Hostname() != "localhost" {
		return "", errors.New("not implemented")
	}

	addr := fmt.Sprintf(":%s", redirectURI.Port())
	if l, err := net.Listen("tcp", addr); err != nil {
		fmt.Fprintf(os.Stderr, "error: port[%s] already used", redirectURI.Port())
		return "", err
	} else {
		l.Close()
	}

	codeCh := make(chan string)
	errCh := make(chan error)
	defer close(codeCh)
	defer close(errCh)

	server := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("callback request: %v\n", r)
			w.Header().Add("Content-Type", "text/plain")
			q := r.URL.Query()
			if code, exists := q["code"]; exists {
				codeCh <- string(code[0])
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(fmt.Sprintf("code: [%s]", string(code[0]))))
			} else {
				errCh <- errors.New("missing code")
				w.WriteHeader(http.StatusBadRequest)
			}
		}),
	}
	defer server.Shutdown(context.TODO())

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		log.Printf("callback server error: %v\n", err)
		return "", err
	case code := <-codeCh:
		return code, nil
	}
}

func authCodeGrant(request *AurlExecution) (*string, error) {
	state := random()
	nonce := random()

	if request.Profile.SSO.Enabled() {
		webbrowser.Open(request.Profile.SSO.SigninURL())
		return receiveTokenFromLocalServerWithSSO(
			request.Profile.SSO.CallbackURI,
			request,
			state,
			nonce,
		)
	}

	authZRequestUrl := authorizationRequestURL("code", request, request.Profile.RedirectURI, state, nonce)
	webbrowser.Open(authZRequestUrl)
	fmt.Fprintf(os.Stderr, "Open browser and get code from %s\n", authZRequestUrl)

	code, err := receiveAuthCodeFromLocalServer(request.Profile.RedirectURI)
	if err != nil {
		code, err = receiveAuthCodeFromStdin()
	}

	if err != nil {
		return nil, err
	} else {
		values := url.Values{
			"grant_type":   {"authorization_code"},
			"code":         {code},
			"redirect_uri": {request.Profile.RedirectURI},
		}
		if pkce := request.Profile.PKCE; pkce.Enabled() {
			values.Add("code_verifier", pkce.CodeVerifier)
		}
		return tokenRequest(values, request)
	}
}

func implicitGrant(request *AurlExecution) (*string, error) {
	state := random()
	nonce := random()
	url := authorizationRequestURL("token", request, request.Profile.RedirectURI, state, nonce)
	webbrowser.Open(url)
	fmt.Fprintf(os.Stderr, "Open browser and get token from %s\n", url)

	reader := bufio.NewReader(os.Stdin)
	fmt.Fprint(os.Stderr, "Enter token: ")
	if token, _, err := reader.ReadLine(); err != nil {
		return nil, err
	} else {
		s := "{\"token_type\": \"bearer\",\"access_token\": \"" + string(token) + "\"}" // TODO
		return &s, nil
	}
}

func resourceOwnerPasswordCredentialsGrant(request *AurlExecution) (*string, error) {
	values := url.Values{
		"grant_type": {"password"},
		"username":   {request.Profile.Username},
		"password":   {request.Profile.Password},
		"scope":      condVal(strings.Join(strings.Split(request.Profile.Scope, ","), " ")),
	}
	return tokenRequest(values, request)
}

func clientCredentialsGrant(request *AurlExecution) (*string, error) {
	values := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      condVal(strings.Join(strings.Split(request.Profile.Scope, ","), " ")),
	}
	return tokenRequest(values, request)
}

func refreshGrant(request *AurlExecution, refreshToken string) (*string, error) {
	values := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"scope":         condVal(strings.Join(strings.Split(request.Profile.Scope, ","), " ")),
	}
	return tokenRequest(values, request)
}

func authorizationRequestURL(responseType string, request *AurlExecution, redirectURI, state, nonce string) string {
	var buf bytes.Buffer
	buf.WriteString(request.Profile.AuthorizationEndpoint)
	v := url.Values{
		"response_type": {responseType},
		"client_id":     {request.Profile.ClientId},
		"redirect_uri":  condVal(redirectURI),
		"scope":         condVal(strings.Join(strings.Split(request.Profile.Scope, ","), " ")),
		"state":         condVal(state),
		"nonce":         condVal(nonce),
	}
	if pkce := request.Profile.PKCE; pkce.Enabled() {
		v.Add("code_challenge", pkce.CodeChallenge)
		v.Add("code_challenge_method", pkce.CodeChallengeMethod)
		v.Add("prompt", "none")
	}
	if strings.Contains(request.Profile.AuthorizationEndpoint, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(v.Encode())
	return buf.String()
}

func tokenRequest(v url.Values, request *AurlExecution) (*string, error) {
	req, err := http.NewRequest("POST", request.Profile.TokenEndpoint, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")

	if request.Headers.Get("User-Agent") != "" {
		req.Header.Add("User-Agent", request.Profile.UserAgent)
	}

	req.SetBasicAuth(request.Profile.ClientId, request.Profile.ClientSecret)

	if dumpReq, err := httputil.DumpRequestOut(req, true); err == nil {
		log.Printf("Token request >>>\n%s\n<<<", string(dumpReq))
	} else {
		log.Printf("Token request dump failed: %s", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: *request.Insecure,
			},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Token request failed: %s", err.Error())
		return nil, err
	}

	defer resp.Body.Close()

	if dumpResp, err := httputil.DumpResponse(resp, true); err == nil {
		log.Printf("Token response >>>\n%s\n<<<", string(dumpResp))
	} else {
		log.Printf("Token response dump failed: %s", err)
	}

	if resp.StatusCode == 200 {
		if b, err := ioutil.ReadAll(resp.Body); err == nil {
			s := string(b)
			return &s, nil
		} else {
			return nil, err
		}
	} else {
		log.Printf("Token request failed: %d", resp.StatusCode)
		return nil, err
	}
}

func condVal(v string) []string {
	if v == "" {
		return nil
	}
	return []string{v}
}

func random() string {
	var n uint64
	binary.Read(rand.Reader, binary.LittleEndian, &n)
	return strconv.FormatUint(n, 36)
}
