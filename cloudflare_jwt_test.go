package traefikcloudflarejwt_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	plugin "github.com/Cyb3r-Jak3/traefikcloudflarejwt"
)

func TestNew(t *testing.T) {
	testCases := []struct {
		desc           string
		CFHeader       string
		PolicyAUD      string
		TeamDomain     string
		expectedStatus int
	}{
		{
			desc:           "no header",
			CFHeader:       "",
			PolicyAUD:      "example",
			TeamDomain:     "example",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			desc:           "invalid header",
			CFHeader:       "invalid",
			PolicyAUD:      "example",
			TeamDomain:     "example",
			expectedStatus: http.StatusForbidden,
		},
		//{
		//	// Reference https://github.com/cloudflare/cloudflared/blob/master/validation/validation_test.go#L290-L304
		//	desc:           "valid header",
		//	CFHeader:       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		//	PolicyAUD:      "",
		//	TeamDomain:     "test",
		//	expectedStatus: http.StatusOK,
		//},
	}
	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			cfg := plugin.CreateConfig()
			cfg.PolicyAUD = test.PolicyAUD
			cfg.TeamDomain = test.TeamDomain
			ctx := context.Background()
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
			handler, err := plugin.New(ctx, next, cfg, "cloudflare_jwt")
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodGet, "https://test.cloudflareaccess.com", nil)
			if test.CFHeader != "" {
				req.Header.Set(plugin.AccessHeaderName, test.CFHeader)
			}
			rw := httptest.NewRecorder()
			handler.ServeHTTP(rw, req)
			if rw.Result().StatusCode != test.expectedStatus {
				t.Errorf("expected status %d, got %d", test.expectedStatus, rw.Code)
			}
		})
	}
}
