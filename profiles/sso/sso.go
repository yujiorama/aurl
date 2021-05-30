package sso

import (
	"fmt"
	"net/url"
)

type SSO struct {
	Endpoint               string
	CallbackQueryParamName string
	CallbackURI            string
}

func New(endpoint, callbackQueryParamName, callbackURI string) SSO {
	return SSO{
		Endpoint:               endpoint,
		CallbackQueryParamName: callbackQueryParamName,
		CallbackURI:            callbackURI,
	}
}

func (sso *SSO) Enabled() bool {
	return sso.Endpoint != ""
}

func (sso *SSO) SigninURL() string {
	if sso.CallbackQueryParamName != "" && sso.CallbackURI != "" {
		v := url.Values{}
		v.Set(sso.CallbackQueryParamName, sso.CallbackURI)
		return fmt.Sprintf("%s?%s", sso.Endpoint, v.Encode())
	}

	return sso.Endpoint
}
