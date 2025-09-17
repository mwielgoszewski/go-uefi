package pkcs7

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"time"

	encasn1 "encoding/asn1"
)

// CreateTimestampRequest creates a RFC 3161 timestamp request
func CreateTimestampRequest(messageImprint []byte, hashAlg pkix.AlgorithmIdentifier) (*TSAReq, error) {
	// Generate a random nonce
	nonce, err := rand.Int(rand.Reader, big.NewInt(1<<63-1))
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	req := &TSAReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: hashAlg,
			HashedMessage: messageImprint,
		},
		Nonce:   nonce,
		CertReq: true,
	}

	return req, nil
}

// RequestTimestamp requests a timestamp from a TSA server
func RequestTimestamp(tsaURL string, req *TSAReq) (*TSAResp, error) {
	// Marshal the timestamp request
	reqBytes, err := encasn1.Marshal(*req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal timestamp request: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequest("POST", tsaURL, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/timestamp-query")
	httpReq.Header.Set("Content-Length", fmt.Sprintf("%d", len(reqBytes)))

	// Send request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send timestamp request: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("timestamp server returned status %d", httpResp.StatusCode)
	}

	// Read response
	respBytes, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read timestamp response: %w", err)
	}

	// Parse the TSA response structure
	// The response is a SEQUENCE containing status and timestamp token
	var outerSeq encasn1.RawValue
	_, err = encasn1.Unmarshal(respBytes, &outerSeq)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TSA response structure: %w", err)
	}

	// The first element should be the PKI status
	var statusSeq encasn1.RawValue
	statusBytes := outerSeq.Bytes
	statusRest, err := encasn1.Unmarshal(statusBytes, &statusSeq)
	if err != nil {
		return nil, fmt.Errorf("failed to parse status sequence: %w", err)
	}

	// Parse the status integer
	var status int
	_, err = encasn1.Unmarshal(statusSeq.Bytes, &status)
	if err != nil {
		return nil, fmt.Errorf("failed to parse status integer: %w", err)
	}

	// Check status
	if status != int(PKIStatusGranted) {
		return nil, fmt.Errorf("timestamp request rejected with status %d", status)
	}

	// The rest is the timestamp token (PKCS#7)
	return &TSAResp{
		Status:  PKIStatusInfo{Status: PKIStatus(status)},
		TSToken: encasn1.RawValue{Bytes: statusRest},
	}, nil
}

// GetTimestamp requests a timestamp for the given message imprint
func GetTimestamp(tsaURL string, messageImprint []byte) ([]byte, error) {
	if tsaURL == "" {
		return nil, errors.New("TSA URL is required")
	}

	// Parse URL to validate
	_, err := url.Parse(tsaURL)
	if err != nil {
		return nil, fmt.Errorf("invalid TSA URL: %w", err)
	}

	// Create hash algorithm identifier for SHA256
	hashAlg := pkix.AlgorithmIdentifier{
		Algorithm:  OIDDigestAlgorithmSHA256,
		Parameters: encasn1.RawValue{Tag: 5}, // ASN.1 NULL
	}

	// Create timestamp request
	req, err := CreateTimestampRequest(messageImprint, hashAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to create timestamp request: %w", err)
	}

	// Request timestamp from server
	resp, err := RequestTimestamp(tsaURL, req)
	if err != nil {
		return nil, fmt.Errorf("failed to request timestamp: %w", err)
	}

	return resp.TSToken.Bytes, nil
}

// VerifyTimestampBytes verifies a RFC 3161 timestamp token and validates it against the provided message imprint.
// It performs the following verifications:
//   - Parses the timestampToken as a PKCS#7 signed data structure
//   - Extracts and validates the TSTInfo (timestamp information)
//   - Verifies the timestamp generation time is within the signing certificate's validity period
//   - Confirms the message imprint in the timestamp matches the provided messageImprint
//   - Validates the TSA certificate chain against trusted roots
//   - Verifies the timestamp signature using the TSA certificate
func VerifyTimestampBytes(timestampToken []byte, messageImprint []byte, signerCert *x509.Certificate, opts ...VerifyOption) error {
	// Parse the timestamp token (which is a PKCS7 signed data structure)
	token, err := ParsePKCS7(timestampToken)
	if err != nil {
		return fmt.Errorf("failed to parse timestamp token: %w", err)
	}

	// Extract TSTInfo using the proper parsing function that handles OCTET STRING wrapping
	tstInfo, err := ParseTimestampInfo(token.ContentInfo)
	if err != nil {
		return fmt.Errorf("failed to parse TSTInfo: %w", err)
	}

	// Ensure generation time is present
	if tstInfo.GenTime.IsZero() {
		return errors.New("timestamp token has no generation time")
	}

	// Verify generation time within certificate validity period
	if tstInfo.GenTime.Before(signerCert.NotBefore) || tstInfo.GenTime.After(signerCert.NotAfter) {
		return errors.New("timestamp generation time is outside the validity period of the signing certificate")
	}

	// Verify the message imprint matches
	if !bytes.Equal(tstInfo.MessageImprint.HashedMessage, messageImprint) {
		return fmt.Errorf("timestamp message imprint does not match %x vs %x", tstInfo.MessageImprint.HashedMessage, messageImprint)
	}

	if len(token.Certs) == 0 {
		return errors.New("no certificates in timestamp token")
	}

	tsaCert := token.Certs[0]

	c := &VerifyConfig{}
	for _, optFunc := range opts {
		optFunc(c)
	}

	if len(c.TSARoots) > 0 {
		intermediatePool := x509.NewCertPool()
		for _, c := range token.Certs[1:] {
			intermediatePool.AddCert(c)
		}
		x509opts := x509.VerifyOptions{
			Roots:         x509.NewCertPool(),
			Intermediates: intermediatePool,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		}
		for _, root := range c.TSARoots {
			x509opts.Roots.AddCert(root)
		}
		if _, err := tsaCert.Verify(x509opts); err != nil {
			return fmt.Errorf("failed to verify TSA certificate: %w", err)
		}
	}

	// Verify the timestamp signature against the TSA certificate
	ok, err := token.Verify(tsaCert)
	if err != nil {
		return fmt.Errorf("failed to verify timestamp signature: %w", err)
	}
	if !ok {
		return fmt.Errorf("timestamp signature verification failed")
	}

	return nil
}

// ParseTimestampInfo parses and extracts TSTInfo (timestamp token information) from PKCS#7 contentInfo.
//
// contentInfo may be the raw ASN.1 encoded content from a PKCS#7 timestamp token, which may be
// either a TSTInfo structure directly or wrapped in an OCTET STRING
func ParseTimestampInfo(contentInfo []byte) (*TSTInfo, error) {
	// Try parsing contentInfo as TSTInfo first
	var tstInfo TSTInfo
	_, err := encasn1.Unmarshal(contentInfo, &tstInfo)
	if err == nil {
		return &tstInfo, nil
	}

	// The content is wrapped in an OCTET STRING, extract it
	var octetString []byte
	_, err = encasn1.Unmarshal(contentInfo, &octetString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OCTET STRING wrapper: %w", err)
	}

	// Parse the octet string content as TSTInfo
	_, err = encasn1.Unmarshal(octetString, &tstInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TSTInfo from OCTET STRING: %w", err)
	}

	return &tstInfo, nil
}
