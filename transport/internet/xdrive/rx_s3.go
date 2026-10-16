// SPDX-License-Identifier: MPL-2.0
//
// S3 storage backend for Xray-core's "xdrive" transport.
//
// xdrive turns any object store into a byte pipe: each side writes numbered
// segment objects under its own prefix and polls the other side's prefix. All
// it needs from a backend is the five-method Storage interface (Put, Get,
// Delete, List, Close). This file implements that interface over the plain S3
// HTTP API with hand-rolled AWS Signature V4, using only the standard library.
//
// Works with VK Cloud (path-style, region ru-msk) and any other S3 endpoint
// that supports ListObjectsV2 with strong list-after-write consistency.
package xdrive

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/xtls/xray-core/transport/internet"
)

const (
	s3BodyLimit = 20 << 20 // hard cap for any request/response body
	s3MaxKeys   = 10000    // listing safety cap
	s3Attempts  = 4        // 1 try + 3 retries on network error / 429 / 5xx
)

// Secrets[0] carries this JSON, so upstream's protobuf schema stays unchanged.
type s3Credentials struct {
	Endpoint  string `json:"endpoint"` // https://hb.ru-msk.vkcloud-storage.ru
	Region    string `json:"region"`   // ru-msk
	Bucket    string `json:"bucket"`
	AccessKey string `json:"accessKey"`
	SecretKey string `json:"secretKey"`
}

type s3Storage struct {
	cred     s3Credentials
	endpoint *url.URL
	prefix   string // RemoteFolder + "/", every object lives under it
	client   *http.Client
}

var (
	s3BucketRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	s3FolderRe = regexp.MustCompile(`^[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*/?$`)
	s3NameRe   = regexp.MustCompile(`^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$`)
)

func newS3Storage(settings *internet.MemoryStreamConfig, config *Config) (*s3Storage, error) {
	if len(config.Secrets) != 1 {
		return nil, errors.New("S3 requires exactly one credentials JSON in secrets")
	}
	var c s3Credentials
	if json.Unmarshal([]byte(config.Secrets[0]), &c) != nil {
		return nil, errors.New("invalid S3 credentials JSON")
	}
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("S3 endpoint must be an https origin without credentials, path or query")
	}
	if !s3BucketRe.MatchString(c.Bucket) || c.Region == "" || c.AccessKey == "" || c.SecretKey == "" {
		return nil, errors.New("S3 bucket, region and credentials are required")
	}
	if !s3FolderRe.MatchString(config.RemoteFolder) {
		return nil, errors.New("S3 requires a non-empty isolated remoteFolder (prefix)")
	}
	client := newServiceClient(settings, 25*time.Second, 8)
	// A redirect would resend the signed request elsewhere; fail closed instead.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &s3Storage{c, u, strings.Trim(config.RemoteFolder, "/") + "/", client}, nil
}

// ---------------------------------------------------------------- SigV4 ----

// s3Escape is the AWS URI-encoding: unreserved characters stay, all else %XX.
func s3Escape(s string, keepSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
			c == '-' || c == '_' || c == '.' || c == '~' || (keepSlash && c == '/') {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func s3CanonicalQuery(q url.Values) string {
	pairs := make([]string, 0, len(q))
	for k, vs := range q {
		for _, v := range vs {
			pairs = append(pairs, s3Escape(k, false)+"="+s3Escape(v, false))
		}
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

func hmacSHA256(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}

// s3Authorize returns the X-Amz-Date and Authorization header values.
// Signed headers are exactly: host, x-amz-content-sha256, x-amz-date.
func s3Authorize(method, host, path, query, payloadHash, access, secret, region string, now time.Time) (string, string) {
	stamp := now.UTC().Format("20060102T150405Z")
	day := stamp[:8]
	const signed = "host;x-amz-content-sha256;x-amz-date"
	headers := "host:" + host + "\nx-amz-content-sha256:" + payloadHash + "\nx-amz-date:" + stamp + "\n"
	canonical := strings.Join([]string{method, path, query, headers, signed, payloadHash}, "\n")
	scope := day + "/" + region + "/s3/aws4_request"
	canonicalHash := sha256.Sum256([]byte(canonical))
	toSign := "AWS4-HMAC-SHA256\n" + stamp + "\n" + scope + "\n" + hex.EncodeToString(canonicalHash[:])
	k := hmacSHA256([]byte("AWS4"+secret), day)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, "s3")
	k = hmacSHA256(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(k, toSign))
	return stamp, "AWS4-HMAC-SHA256 Credential=" + access + "/" + scope +
		", SignedHeaders=" + signed + ", Signature=" + sig
}

// -------------------------------------------------------------- requests ----

func (s *s3Storage) request(ctx context.Context, method, key string, query url.Values, data []byte) (int, []byte, error) {
	if len(data) > s3BodyLimit {
		return 0, nil, errors.New("S3 segment too large")
	}
	path := "/" + s.cred.Bucket // path-style addressing (VK Cloud, MinIO, ...)
	if key != "" {
		path += "/" + s3Escape(key, true)
	}
	cq := s3CanonicalQuery(query)
	full := s.endpoint.Scheme + "://" + s.endpoint.Host + path
	if cq != "" {
		full += "?" + cq
	}
	digest := sha256.Sum256(data)
	hash := hex.EncodeToString(digest[:])

	for attempt := 0; attempt < s3Attempts; attempt++ {
		if attempt > 0 { // 100ms, 200ms, 400ms
			select {
			case <-ctx.Done():
				return 0, nil, ctx.Err()
			case <-time.After(time.Duration(100<<uint(attempt-1)) * time.Millisecond):
			}
		}
		req, err := http.NewRequestWithContext(ctx, method, full, bytes.NewReader(data))
		if err != nil {
			return 0, nil, errors.New("invalid S3 request")
		}
		// A fresh timestamp per attempt: retries must not outlive the 15-min skew window.
		stamp, auth := s3Authorize(method, req.URL.Host, path, cq, hash,
			s.cred.AccessKey, s.cred.SecretKey, s.cred.Region, time.Now())
		req.Header.Set("X-Amz-Date", stamp)
		req.Header.Set("X-Amz-Content-Sha256", hash)
		req.Header.Set("Authorization", auth)

		resp, err := s.client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return 0, nil, ctx.Err()
			}
			if attempt < s3Attempts-1 {
				continue
			}
			return 0, nil, errors.New("S3 network or certificate error")
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, s3BodyLimit+1))
		resp.Body.Close()
		if readErr != nil {
			return 0, nil, errors.New("S3 response read failed")
		}
		if len(body) > s3BodyLimit {
			return 0, nil, errors.New("S3 response exceeds safety limit")
		}
		if (resp.StatusCode == 429 || resp.StatusCode >= 500) && attempt < s3Attempts-1 {
			continue
		}
		return resp.StatusCode, body, nil
	}
	return 0, nil, errors.New("S3 retry budget exhausted")
}

// Never log response bodies: S3 errors can echo canonical requests and keys.
func s3Status(op string, status int) error { return fmt.Errorf("S3 %s HTTP %d", op, status) }

func safeS3Name(name string) bool {
	if !s3NameRe.MatchString(name) {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}

// ------------------------------------------------- Storage implementation ----

func (s *s3Storage) Put(ctx context.Context, name string, data []byte) error {
	if !safeS3Name(name) {
		return errors.New("unsafe S3 object name")
	}
	status, _, err := s.request(ctx, "PUT", s.prefix+name, nil, data)
	if err != nil {
		return err
	}
	if status/100 != 2 {
		return s3Status("PUT", status)
	}
	return nil
}

func (s *s3Storage) Get(ctx context.Context, name string) ([]byte, error) {
	if !safeS3Name(name) {
		return nil, errors.New("unsafe S3 object name")
	}
	status, body, err := s.request(ctx, "GET", s.prefix+name, nil, nil)
	if err != nil {
		return nil, err
	}
	if status == 404 {
		return nil, errNotFound // xdrive treats this as "not there yet", not fatal
	}
	if status != 200 {
		return nil, s3Status("GET", status)
	}
	return body, nil
}

type s3Listing struct {
	Truncated bool   `xml:"IsTruncated"`
	Token     string `xml:"NextContinuationToken"`
	Contents  []struct {
		Key string `xml:"Key"`
	} `xml:"Contents"`
	Common []struct {
		Prefix string `xml:"Prefix"`
	} `xml:"CommonPrefixes"`
}

// listKeys runs ListObjectsV2. recursive=false adds delimiter "/", so S3 groups
// deeper keys into CommonPrefixes — that is how a flat store imitates folders.
func (s *s3Storage) listKeys(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	q := url.Values{"list-type": {"2"}, "prefix": {prefix}, "max-keys": {"1000"}}
	if !recursive {
		q.Set("delimiter", "/")
	}
	var keys []string
	seen := map[string]bool{}
	for page := 0; page < 100; page++ {
		status, body, err := s.request(ctx, "GET", "", q, nil)
		if err != nil {
			return nil, err
		}
		if status != 200 {
			return nil, s3Status("LIST", status)
		}
		var l s3Listing
		if xml.Unmarshal(body, &l) != nil {
			return nil, errors.New("invalid S3 listing XML")
		}
		add := func(k string) error {
			if !strings.HasPrefix(k, prefix) {
				return errors.New("S3 returned an object outside the requested prefix")
			}
			if !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
			if len(keys) > s3MaxKeys {
				return errors.New("S3 listing safety limit reached; clean stale sessions")
			}
			return nil
		}
		for _, c := range l.Contents {
			if err := add(c.Key); err != nil {
				return nil, err
			}
		}
		for _, c := range l.Common {
			if err := add(c.Prefix); err != nil {
				return nil, err
			}
		}
		if !l.Truncated {
			return keys, nil
		}
		if l.Token == "" || l.Token == q.Get("continuation-token") {
			return nil, errors.New("invalid S3 pagination token")
		}
		q.Set("continuation-token", l.Token)
	}
	return nil, errors.New("S3 pagination limit reached")
}

// List returns the direct children (names only) of "<prefix>/", like readdir.
func (s *s3Storage) List(ctx context.Context, prefix string) ([]Entry, error) {
	if !safeS3Name(prefix) {
		return nil, errors.New("unsafe S3 prefix")
	}
	root := s.prefix + prefix + "/"
	keys, err := s.listKeys(ctx, root, false)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(keys))
	for _, k := range keys {
		name := strings.TrimSuffix(strings.TrimPrefix(k, root), "/")
		if name != "" && !strings.Contains(name, "/") {
			out = append(out, Entry{Name: name})
		}
	}
	return out, nil
}

func (s *s3Storage) deleteKey(ctx context.Context, key string) error {
	status, _, err := s.request(ctx, "DELETE", key, nil, nil)
	if err != nil {
		return err
	}
	if status != 404 && status/100 != 2 { // deleting a missing object is success
		return s3Status("DELETE", status)
	}
	return nil
}

// Delete removes one object. xdrive also calls it on a whole session folder
// ("streams/<sid>"); S3 has no folders, so that case lists and deletes
// everything beneath it (the local backend does the same with os.RemoveAll).
func (s *s3Storage) Delete(ctx context.Context, name string) error {
	if !safeS3Name(name) {
		return errors.New("unsafe S3 object name")
	}
	key := s.prefix + name
	if strings.HasPrefix(name, "streams/") && strings.Count(name, "/") == 1 {
		keys, err := s.listKeys(ctx, key+"/", true)
		if err != nil {
			return err
		}
		for _, k := range keys {
			if err := s.deleteKey(ctx, k); err != nil {
				return err
			}
		}
		return nil
	}
	return s.deleteKey(ctx, key)
}

func (s *s3Storage) Close() error { return nil }
