package pkcs7

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"time"

	encasn1 "encoding/asn1"
)

// OID data we need
var (
	OIDData                        = encasn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDSignedData                  = encasn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDDigestAlgorithmSHA256       = encasn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDDigestAlgorithmSHA384       = encasn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDDigestAlgorithmSHA512       = encasn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	OIDEncryptionAlgorithmRSA      = encasn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	OIDAttributeContentType        = encasn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	OIDAttributeMessageDigest      = encasn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	OIDAttributeSigningTime        = encasn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	OIDAttributeTSTInfo            = encasn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	OIDAttributeRFC3161TimeStamp   = encasn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}
	OIDAttributeMicrosoftTimeStamp = encasn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 3, 3, 1}
)

var digestAlgorithmHashFunction = map[string]crypto.Hash{
	OIDDigestAlgorithmSHA256.String(): crypto.SHA256,
	OIDDigestAlgorithmSHA384.String(): crypto.SHA384,
	OIDDigestAlgorithmSHA512.String(): crypto.SHA512,
}

// Common errors
var (
	// ASN.1 parsing errors
	ErrInteger     = errors.New("expected INTEGER")
	ErrObjectID    = errors.New("expected OBJECT IDENTIFIER")
	ErrNull        = errors.New("expected NULL")
	ErrSequence    = errors.New("expected SEQUENCE")
	ErrOctetString = errors.New("expected OCTET STRING")

	// PKCS7 processing errors
	ErrNoCertificate     = errors.New("no valid certificates")
	ErrTimestampRequest  = errors.New("timestamp request failed")
	ErrTimestampResponse = errors.New("invalid timestamp response")
	ErrTimestampVerify   = errors.New("timestamp verification failed")
)

type Config struct {
	NoAttr                   bool
	NoCerts                  bool
	AdditionalCerts          []*x509.Certificate
	TimestampURL             string
	UseMicrosoftTimestampOID bool
}

// TSAPolicyId represents a timestamp policy identifier
type TSAPolicyId encasn1.ObjectIdentifier

// TSAQualifier represents a timestamp qualifier
type TSAQualifier struct {
	Qualifier string
}

// MessageImprint contains the hash of the data to be time-stamped
type MessageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

// TSAReq represents a Time Stamp Request as defined in RFC 3161
type TSAReq struct {
	Version        int
	MessageImprint MessageImprint
	ReqPolicy      TSAPolicyId      `asn1:"optional"`
	Nonce          *big.Int         `asn1:"optional"`
	CertReq        bool             `asn1:"optional"`
	Extensions     []pkix.Extension `asn1:"tag:0,optional"`
}

// PKIStatus represents the status of a PKI response
type PKIStatus int

const (
	PKIStatusGranted                PKIStatus = 0
	PKIStatusGrantedWithMods        PKIStatus = 1
	PKIStatusRejection              PKIStatus = 2
	PKIStatusWaiting                PKIStatus = 3
	PKIStatusRevocationWarning      PKIStatus = 4
	PKIStatusRevocationNotification PKIStatus = 5
)

// PKIFreeText represents free text in a PKI response
type PKIFreeText []string

// PKIFailureInfo represents failure information
type PKIFailureInfo encasn1.BitString

// PKIStatus contains the status information of a timestamp response
type PKIStatusInfo struct {
	Status       PKIStatus      `asn1:""`
	StatusString PKIFreeText    `asn1:"optional"`
	FailInfo     PKIFailureInfo `asn1:"optional"`
}

// TSAResp represents a Time Stamp Response as defined in RFC 3161
type TSAResp struct {
	Status  PKIStatusInfo    `asn1:""`
	TSToken encasn1.RawValue `asn1:"optional"`
}

// TSTInfo represents the timestamp info structure
type TSTInfo struct {
	Version        int                      `asn1:""`
	Policy         encasn1.ObjectIdentifier `asn1:""`
	MessageImprint MessageImprint           `asn1:""`
	SerialNumber   *big.Int                 `asn1:""`
	GenTime        time.Time                `asn1:"generalized"`
	Accuracy       Accuracy                 `asn1:"optional"`
	Ordering       bool                     `asn1:"optional"`
	Nonce          *big.Int                 `asn1:"optional"`
	TSA            []byte                   `asn1:"tag:0,optional"`
	Extensions     []pkix.Extension         `asn1:"tag:1,optional"`
}

// Accuracy represents timestamp accuracy
type Accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"tag:0,optional"`
	Micros  int `asn1:"tag:1,optional"`
}

type Option func(*Config)

type VerifyConfig struct {
	VerifyTimestamp bool
	TSARoots        []*x509.Certificate // Trusted root CAs for TSA certificates
}

type VerifyOption func(*VerifyConfig)

type issuerAndSerialNumber struct {
	RawIssuer    []byte
	SerialNumber *big.Int
}

type signerinfo struct {
	Version                   int64
	EncryptedDigest           []byte
	DigestAlgorithm           *pkix.AlgorithmIdentifier
	AuthenticatedAttributes   *Attributes
	EncryptedDigestAlgorithm  *pkix.AlgorithmIdentifier
	IssuerAndSerialnumber     *issuerAndSerialNumber
	UnauthenticatedAttributes *Attributes
	TimestampToken            []byte // Store timestamp for unauthenticated attributes
}

type PKCS7 struct {
	OID                 encasn1.ObjectIdentifier
	SignerInfo          []*signerinfo
	ContentInfo         []byte
	Certs               []*x509.Certificate
	AlgorithmIdentifier *pkix.AlgorithmIdentifier
}

type unparsedAttribute struct {
	Type  encasn1.ObjectIdentifier
	Bytes []byte
}

type Attributes struct {
	ContentType    encasn1.ObjectIdentifier
	MessageDigest  []byte
	SigningTime    time.Time
	TimestampToken []byte
	Other          []*unparsedAttribute
	RawBytes       []byte // Store the original DER bytes for signature verification
}
