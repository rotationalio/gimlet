package quarterdeck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"

	"go.rtnl.ai/gimlet/auth"
	"go.rtnl.ai/gimlet/logger"
	"go.rtnl.ai/ulid"
	"go.rtnl.ai/x/httpcc"
)

//===========================================================================
// HTTP Methods
//===========================================================================

const (
	userAgent    = "Gimlet Quarterdeck Client/v1"
	accept       = "application/json"
	acceptLang   = "en-US,en"
	acceptEncode = "gzip, deflate, br"
	contentType  = "application/json; charset=utf-8"
)

func (s *Quarterdeck) NewRequest(ctx context.Context, method, url string, body io.Reader) (req *http.Request, err error) {
	if req, err = http.NewRequestWithContext(ctx, method, url, body); err != nil {
		return nil, fmt.Errorf("could not create request: %w", err)
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", accept)
	req.Header.Set("Accept-Language", acceptLang)
	req.Header.Set("Accept-Encoding", acceptEncode)
	req.Header.Set("Content-Type", contentType)

	// Set If-Not-Match header if ETag is available
	if etag, ok := s.etag[url]; ok {
		req.Header.Set("If-None-Match", etag)
	}

	var requestID string
	if requestID, _ = logger.RequestID(ctx); requestID == "" {
		requestID = ulid.Make().String()
	}
	req.Header.Add("X-Request-ID", requestID)

	return req, nil
}

func (s *Quarterdeck) Do(req *http.Request, data interface{}) (rep *http.Response, err error) {
	if rep, err = s.client.Do(req); err != nil {
		return nil, fmt.Errorf("could not execute request: %w", err)
	}
	defer rep.Body.Close()

	if rep.StatusCode < 200 || rep.StatusCode >= 300 {
		// If the status coded is 304 Not Modified, return a use cache error message
		if rep.StatusCode == http.StatusNotModified {
			return nil, auth.ErrNotModified
		}

		out := make(map[string]interface{})
		json.NewDecoder(rep.Body).Decode(&out)

		if errMsg, ok := out["error"]; ok {
			return nil, fmt.Errorf("[%d] %s", rep.StatusCode, errMsg)
		}
		return nil, fmt.Errorf("[%d] %s", rep.StatusCode, http.StatusText(rep.StatusCode))
	}

	// Parse the cache control headers
	var directive *httpcc.ResponseDirective
	if directive, err = httpcc.Response(rep); err != nil {
		return nil, fmt.Errorf("could not parse response headers: %w", err)
	}

	// Set the ETag if it's available in the response headers
	if etag, ok := directive.ETag(); ok {
		s.etag[req.URL.String()] = etag
	}

	// Determine when the cache should expire and we should request the data again.
	if expires, ok := directive.Expires(); ok {
		// Prioritize the Expires header from the Cache-Control directive
		s.expires[req.URL.String()] = expires
	} else if maxAge, ok := directive.MaxAge(); ok {
		// Otherwise, use the Max-Age directive from Cache-Control
		s.expires[req.URL.String()] = time.Now().Add(time.Duration(maxAge) * time.Second)
	} else {
		// Default to the current time plus the sync interval if no expiration is set
		s.expires[req.URL.String()] = time.Now().Add(SyncInterval)
	}

	// Deserialize the JSON data from the body
	if data != nil && rep.StatusCode >= 200 && rep.StatusCode < 300 && rep.StatusCode != http.StatusNoContent {
		ct := rep.Header.Get("Content-Type")
		if ct != "" {
			mt, _, err := mime.ParseMediaType(ct)
			if err != nil {
				return nil, fmt.Errorf("malformed content-type header: %w", err)
			}

			if mt != accept {
				return nil, fmt.Errorf("unexpected content type: %q", mt)
			}
		}

		if err = json.NewDecoder(rep.Body).Decode(data); err != nil {
			return nil, fmt.Errorf("could not deserialize response data: %s", err)
		}
	}
	return rep, nil
}
