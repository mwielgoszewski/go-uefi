package pkcs7

import (
	"crypto/x509/pkix"
	encasn1 "encoding/asn1"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// TimeAttributeCertificate represents a Thales TSS Time Attribute Certificate.
// This is placed in the [1] slot of CertificateSet when using
// "CertificateChoices1 with ESSCertID compatibility mode".
type TimeAttributeCertificate struct {
	Version         int64
	Holder          pkix.RDNSequence          // The entity this TAC is for (as GeneralName [1] directoryName)
	Issuer          pkix.RDNSequence          // The TSA that issued this TAC (as GeneralName [0] directoryName)
	DigestAlgorithm *pkix.AlgorithmIdentifier // Digest algorithm used
	DigestValue     []byte                    // Hash value in [2] tag
	SignatureAlgo   *pkix.AlgorithmIdentifier // Signature algorithm
	SerialNumber    []byte                    // Serial number of the TAC
	NotBefore       time.Time                 // Validity period start
	NotAfter        time.Time                 // Validity period end
	TimingAttrs     []Attribute               // Timing policy and metrics attributes
	Signature       []byte                    // Signature value
}

// Attribute represents a generic CMS attribute
type Attribute struct {
	Type   encasn1.ObjectIdentifier
	Values [][]byte
}

// BigTime represents a high-precision timestamp with major and fractional seconds
// From Bancomm timing specification (OID 1.3.6.1.4.1.601)
type BigTime struct {
	Major      int64 // Major time component (seconds since epoch or similar)
	Fractional int64 // Fractional seconds component
	Sign       int   // Optional sign indicator (0=positive, 1=negative)
}

// LeapData represents leap second event information
type LeapData struct {
	LeapTime BigTime
	Action   int // Leap second action (add/subtract)
}

// TimingMetrics represents Bancomm timing quality metrics (OID 1.3.6.1.4.1.601.10.4.1)
type TimingMetrics struct {
	NTPTime    BigTime    // Network Time Protocol timestamp
	Offset     BigTime    // Time offset from reference
	Delay      BigTime    // Network delay measurement
	Expiration BigTime    // Expiration time for this metric
	LeapEvents []LeapData // Optional leap second events
}

// TimingPolicy represents Bancomm timing policy (OID 1.3.6.1.4.1.601.10.4.2)
type TimingPolicy struct {
	PolicyIDs []encasn1.ObjectIdentifier // Policy identifiers
	MaxOffset *BigTime                    // Maximum allowed offset [0] OPTIONAL
	MaxDelay  *BigTime                    // Maximum allowed delay [1] OPTIONAL
}

// parseBigTime parses a BigTime structure from Bancomm timing specification
func parseBigTime(s *cryptobyte.String) (BigTime, error) {
	var bt BigTime
	var btSeq cryptobyte.String

	if !s.ReadASN1(&btSeq, asn1.SEQUENCE) {
		return bt, errors.New("failed to read BigTime SEQUENCE")
	}

	// Read major INTEGER
	if !btSeq.ReadASN1Integer(&bt.Major) {
		return bt, errors.New("failed to read BigTime major")
	}

	// Read fractional Seconds INTEGER
	if !btSeq.ReadASN1Integer(&bt.Fractional) {
		return bt, errors.New("failed to read BigTime fractional")
	}

	// Read optional sign INTEGER
	if !btSeq.Empty() && btSeq.PeekASN1Tag(asn1.INTEGER) {
		var sign int64
		if btSeq.ReadASN1Integer(&sign) {
			bt.Sign = int(sign)
		}
	}

	return bt, nil
}

// parseTimingMetrics parses TimingMetrics (OID 1.3.6.1.4.1.601.10.4.1)
func parseTimingMetrics(data []byte) (*TimingMetrics, error) {
	s := cryptobyte.String(data)
	var tm TimingMetrics
	var metricsSeq cryptobyte.String

	if !s.ReadASN1(&metricsSeq, asn1.SEQUENCE) {
		return nil, errors.New("failed to read TimingMetrics SEQUENCE")
	}

	// Read NTPTime
	var err error
	tm.NTPTime, err = parseBigTime(&metricsSeq)
	if err != nil {
		return nil, fmt.Errorf("failed to parse NTPTime: %w", err)
	}

	// Read offset
	tm.Offset, err = parseBigTime(&metricsSeq)
	if err != nil {
		return nil, fmt.Errorf("failed to parse offset: %w", err)
	}

	// Read delay
	tm.Delay, err = parseBigTime(&metricsSeq)
	if err != nil {
		return nil, fmt.Errorf("failed to parse delay: %w", err)
	}

	// Read expiration
	tm.Expiration, err = parseBigTime(&metricsSeq)
	if err != nil {
		return nil, fmt.Errorf("failed to parse expiration: %w", err)
	}

	// Read optional leapEvent SET OF LeapData
	if !metricsSeq.Empty() && metricsSeq.PeekASN1Tag(asn1.SET) {
		var leapSet cryptobyte.String
		if !metricsSeq.ReadASN1(&leapSet, asn1.SET) {
			return nil, errors.New("failed to read leapEvent SET")
		}

		for !leapSet.Empty() {
			var ld LeapData
			ld.LeapTime, err = parseBigTime(&leapSet)
			if err != nil {
				break
			}

			var action int64
			if !leapSet.ReadASN1Integer(&action) {
				break
			}
			ld.Action = int(action)

			tm.LeapEvents = append(tm.LeapEvents, ld)
		}
	}

	return &tm, nil
}

// parseTimingPolicy parses TimingPolicy (OID 1.3.6.1.4.1.601.10.4.2)
func parseTimingPolicy(data []byte) (*TimingPolicy, error) {
	s := cryptobyte.String(data)
	var tp TimingPolicy
	var policySeq cryptobyte.String

	if !s.ReadASN1(&policySeq, asn1.SEQUENCE) {
		return nil, errors.New("failed to read TimingPolicy SEQUENCE")
	}

	// Read policyID SEQUENCE SIZE (1..MAX) OF OBJECT IDENTIFIER
	var policyIDSeq cryptobyte.String
	if !policySeq.ReadASN1(&policyIDSeq, asn1.SEQUENCE) {
		return nil, errors.New("failed to read policyID SEQUENCE")
	}

	for !policyIDSeq.Empty() {
		var oid encasn1.ObjectIdentifier
		if !policyIDSeq.ReadASN1ObjectIdentifier(&oid) {
			break
		}
		tp.PolicyIDs = append(tp.PolicyIDs, oid)
	}

	// Read optional maxOffset [0] BigTime
	if !policySeq.Empty() && policySeq.PeekASN1Tag(asn1.Tag(0).ContextSpecific().Constructed()) {
		var maxOffsetTag cryptobyte.String
		if !policySeq.ReadASN1(&maxOffsetTag, asn1.Tag(0).ContextSpecific().Constructed()) {
			return nil, errors.New("failed to read maxOffset [0] tag")
		}

		maxOffset, err := parseBigTime(&maxOffsetTag)
		if err != nil {
			return nil, fmt.Errorf("failed to parse maxOffset: %w", err)
		}
		tp.MaxOffset = &maxOffset
	}

	// Read optional maxDelay [1] BigTime
	if !policySeq.Empty() && policySeq.PeekASN1Tag(asn1.Tag(1).ContextSpecific().Constructed()) {
		var maxDelayTag cryptobyte.String
		if !policySeq.ReadASN1(&maxDelayTag, asn1.Tag(1).ContextSpecific().Constructed()) {
			return nil, errors.New("failed to read maxDelay [1] tag")
		}

		maxDelay, err := parseBigTime(&maxDelayTag)
		if err != nil {
			return nil, fmt.Errorf("failed to parse maxDelay: %w", err)
		}
		tp.MaxDelay = &maxDelay
	}

	return &tp, nil
}

// parseTimeAttributeCertificate parses a Thales TSS Time Attribute Certificate.
// TAC Structure:
//
//	SEQUENCE {
//	  version INTEGER (1)
//	  holder [1] IMPLICIT GeneralNames ([4] directoryName with issuer DN)
//	  digestAlgorithm AlgorithmIdentifier
//	  authenticatedAttributes [0] IMPLICIT Attributes
//	  signatureAlgorithm AlgorithmIdentifier
//	  signatureValue BIT STRING
//	}
func parseTimeAttributeCertificate(der *cryptobyte.String) (*TimeAttributeCertificate, error) {
	var tac TimeAttributeCertificate
	var tacSeq cryptobyte.String

	if !der.ReadASN1(&tacSeq, asn1.SEQUENCE) {
		return nil, errors.New("failed to read TAC SEQUENCE")
	}

	// Read version
	if !tacSeq.ReadASN1Integer(&tac.Version) {
		return nil, errors.New("failed to read TAC version")
	}

	// Read the next SEQUENCE which contains holder and issuer info
	var innerSeq cryptobyte.String
	if !tacSeq.ReadASN1(&innerSeq, asn1.SEQUENCE) {
		return nil, errors.New("failed to read inner SEQUENCE after version")
	}

	// Read holder [1] IMPLICIT GeneralNames
	// The holder is typically [1] -> [4] -> DN
	if innerSeq.PeekASN1Tag(asn1.Tag(1).ContextSpecific().Constructed()) {
		var holderTag cryptobyte.String
		if !innerSeq.ReadASN1(&holderTag, asn1.Tag(1).ContextSpecific().Constructed()) {
			return nil, errors.New("failed to read holder [1] tag")
		}

		// Inside [1] is [4] directoryName containing the DN
		if holderTag.PeekASN1Tag(asn1.Tag(4).ContextSpecific().Constructed()) {
			var dnSeq cryptobyte.String
			if !holderTag.ReadASN1(&dnSeq, asn1.Tag(4).ContextSpecific().Constructed()) {
				return nil, errors.New("failed to read holder [4] directoryName")
			}

			// Parse the DN
			var holderDNBytes cryptobyte.String
			if !dnSeq.ReadASN1Element(&holderDNBytes, asn1.SEQUENCE) {
				return nil, errors.New("failed to read holder DN SEQUENCE")
			}

			var holderRDN pkix.RDNSequence
			if _, err := encasn1.Unmarshal(holderDNBytes, &holderRDN); err != nil {
				return nil, fmt.Errorf("failed to unmarshal holder DN: %w", err)
			}
			tac.Holder = holderRDN
		}
	}

	// Read [2] tag which contains issuer info and digest algorithm
	// Structure: [2] { ENUMERATED(version), AlgorithmIdentifier, BIT STRING(hash), ... }
	if innerSeq.PeekASN1Tag(asn1.Tag(2).ContextSpecific().Constructed()) {
		var tag2Data cryptobyte.String
		if !innerSeq.ReadASN1(&tag2Data, asn1.Tag(2).ContextSpecific().Constructed()) {
			return nil, errors.New("failed to read [2] tag")
		}

		// Skip ENUMERATED version if present
		if tag2Data.PeekASN1Tag(asn1.ENUM) {
			var enumVal int
			tag2Data.ReadASN1Enum(&enumVal)
		}

		// Read digest algorithm
		if tag2Data.PeekASN1Tag(asn1.SEQUENCE) {
			algo, err := ParseAlgorithmIdentifier(&tag2Data)
			if err != nil {
				return nil, fmt.Errorf("failed to parse digest algorithm: %w", err)
			}
			tac.DigestAlgorithm = algo
		}

		// Read digest value (BIT STRING)
		if tag2Data.PeekASN1Tag(asn1.BIT_STRING) {
			var bitString encasn1.BitString
			if !tag2Data.ReadASN1BitString(&bitString) {
				return nil, errors.New("failed to read digest value BIT STRING")
			}
			tac.DigestValue = bitString.Bytes
		}
	}

	// After the inner SEQUENCE, parse remaining fields at depth 14
	// Read issuer [0] IMPLICIT
	if tacSeq.PeekASN1Tag(asn1.Tag(0).ContextSpecific().Constructed()) {
		var issuerTag cryptobyte.String
		if !tacSeq.ReadASN1(&issuerTag, asn1.Tag(0).ContextSpecific().Constructed()) {
			return nil, errors.New("failed to read issuer [0] tag")
		}

		// Inside [0] is SEQUENCE containing [4] directoryName
		var issuerSeq cryptobyte.String
		if !issuerTag.ReadASN1(&issuerSeq, asn1.SEQUENCE) {
			return nil, errors.New("failed to read issuer SEQUENCE")
		}

		// Inside SEQUENCE is [4] directoryName
		if issuerSeq.PeekASN1Tag(asn1.Tag(4).ContextSpecific().Constructed()) {
			var dnSeq cryptobyte.String
			if !issuerSeq.ReadASN1(&dnSeq, asn1.Tag(4).ContextSpecific().Constructed()) {
				return nil, errors.New("failed to read issuer [4] directoryName")
			}

			var issuerDNBytes cryptobyte.String
			if !dnSeq.ReadASN1Element(&issuerDNBytes, asn1.SEQUENCE) {
				return nil, errors.New("failed to read issuer DN SEQUENCE")
			}

			var issuerRDN pkix.RDNSequence
			if _, err := encasn1.Unmarshal(issuerDNBytes, &issuerRDN); err != nil {
				return nil, fmt.Errorf("failed to unmarshal issuer DN: %w", err)
			}
			tac.Issuer = issuerRDN
		}
	}

	// Read signature algorithm SEQUENCE
	if tacSeq.PeekASN1Tag(asn1.SEQUENCE) {
		algo, err := ParseAlgorithmIdentifier(&tacSeq)
		if err != nil {
			return nil, fmt.Errorf("failed to parse signature algorithm: %w", err)
		}
		tac.SignatureAlgo = algo
	}

	// Read serial number INTEGER
	if tacSeq.PeekASN1Tag(asn1.INTEGER) {
		var serialNum []byte
		if !tacSeq.ReadASN1Bytes(&serialNum, asn1.INTEGER) {
			return nil, errors.New("failed to read serial number")
		}
		tac.SerialNumber = serialNum
	}

	// Read validity period SEQUENCE
	if tacSeq.PeekASN1Tag(asn1.SEQUENCE) {
		var validitySeq cryptobyte.String
		if !tacSeq.ReadASN1(&validitySeq, asn1.SEQUENCE) {
			return nil, errors.New("failed to read validity SEQUENCE")
		}

		// Read NotBefore
		if !validitySeq.ReadASN1GeneralizedTime(&tac.NotBefore) {
			return nil, errors.New("failed to read notBefore")
		}

		// Read NotAfter
		if !validitySeq.ReadASN1GeneralizedTime(&tac.NotAfter) {
			return nil, errors.New("failed to read notAfter")
		}
	}

	// Read timing attributes SEQUENCE (optional)
	if tacSeq.PeekASN1Tag(asn1.SEQUENCE) {
		var attrsSeq cryptobyte.String
		if !tacSeq.ReadASN1(&attrsSeq, asn1.SEQUENCE) {
			return nil, errors.New("failed to read timing attributes SEQUENCE")
		}

		// Parse each attribute
		for !attrsSeq.Empty() {
			var attrSeq cryptobyte.String
			if !attrsSeq.ReadASN1(&attrSeq, asn1.SEQUENCE) {
				break
			}

			var attr Attribute
			if !attrSeq.ReadASN1ObjectIdentifier(&attr.Type) {
				break
			}

			// Read SET OF values
			var valuesSet cryptobyte.String
			if !attrSeq.ReadASN1(&valuesSet, asn1.SET) {
				break
			}

			// Read each value
			for !valuesSet.Empty() {
				var value cryptobyte.String
				var tag asn1.Tag
				if !valuesSet.ReadAnyASN1Element(&value, &tag) {
					break
				}
				attr.Values = append(attr.Values, []byte(value))
			}

			tac.TimingAttrs = append(tac.TimingAttrs, attr)
		}
	}

	// After the main TAC SEQUENCE (tacSeq), there should be more data in der:
	// - SEQUENCE: final signature algorithm (at depth 13, sibling to main SEQUENCE)
	// - BIT STRING: signature value (at depth 13)

	// Read final signature algorithm from der (after the main SEQUENCE)
	if !der.Empty() && der.PeekASN1Tag(asn1.SEQUENCE) {
		var finalSigAlgo cryptobyte.String
		der.ReadASN1(&finalSigAlgo, asn1.SEQUENCE)
		// This is typically a duplicate of the signature algorithm we already have
	}

	// Read signature BIT STRING from der
	if !der.Empty() && der.PeekASN1Tag(asn1.BIT_STRING) {
		var bitString encasn1.BitString
		if der.ReadASN1BitString(&bitString) {
			tac.Signature = bitString.Bytes
		}
	}

	return &tac, nil
}

// ParseExtendedCertData attempts to parse extended certificate data found in the certificates section.
// Per RFC 5652 Section 10.2.2, CertificateSet can contain:
//   - X.509 certificates (untagged SEQUENCE)
//   - [0] PKCS#6 extended certificates (obsolete, not recommended)
//   - [1] v1 attribute certificates (obsolete, not recommended)
//   - [2] v2 attribute certificates
//   - [3] other certificate formats
//
// Thales nCipher Time Stamp Servers use "CertificateChoices1 with ESSCertID compatibility mode"
// which places proprietary Time Attribute Certificates (TAC) in the [1] slot. While RFC 5652
// designates [1] for v1 attribute certificates, the Thales TAC is NOT a standard RFC v1 AC.
// Instead, it's a Thales-specific format containing timing policy and metrics information,
// with holder/issuer using GeneralName [1]/[4] directoryName format.
func ParseExtendedCertData(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	s := cryptobyte.String(data)

	// Try to identify what we're looking at
	for !s.Empty() {
		// Check if this is a [1] context-specific constructed tag (unauthenticated attributes)
		if s.PeekASN1Tag(asn1.Tag(1).ContextSpecific().Constructed()) {
			var unauthData cryptobyte.String
			if !s.ReadASN1(&unauthData, asn1.Tag(1).ContextSpecific().Constructed()) {
				return errors.New("failed to read [1] unauthenticated attributes tag")
			}

			fmt.Printf("Found [1] Time Attribute Certificate (%d bytes)\n", len(unauthData))

			// Per RFC 5652, [1] in CertificateSet is designated for v1 attribute certificates.
			// Thales TSS servers use this slot for Time Attribute Certificates (TAC) in
			// "CertificateChoices1 with ESSCertID compatibility mode".
			// NOTE: This is NOT a standard RFC v1 AttributeCertificate structure, but rather
			// a proprietary Thales format that uses the [1] slot for placement.

			// Check if it starts with a SEQUENCE (Time Attribute Certificate structure)
			if unauthData.PeekASN1Tag(asn1.SEQUENCE) {
				fmt.Printf("  -> Contains Time Attribute Certificate (Thales TSS format)\n")

				// Parse the Time Attribute Certificate
				tac, err := parseTimeAttributeCertificate(&unauthData)
				if err != nil {
					fmt.Printf("     Error parsing TAC: %v\n", err)
					fmt.Printf("     This TAC may use a variant format not fully supported\n")
				} else {
					fmt.Printf("     Version: %d\n", tac.Version)

					if len(tac.Holder) > 0 {
						holderName := pkix.Name{}
						holderName.FillFromRDNSequence(&tac.Holder)
						fmt.Printf("     Holder: %s\n", holderName.String())
					}

					if len(tac.Issuer) > 0 {
						issuerName := pkix.Name{}
						issuerName.FillFromRDNSequence(&tac.Issuer)
						fmt.Printf("     Issuer: %s\n", issuerName.String())
					}

					if tac.DigestAlgorithm != nil {
						fmt.Printf("     Digest Algorithm: %s\n", tac.DigestAlgorithm.Algorithm.String())
					}

					if len(tac.DigestValue) > 0 {
						fmt.Printf("     Digest Value: %x\n", tac.DigestValue)
					}

					if tac.SignatureAlgo != nil {
						fmt.Printf("     Signature Algorithm: %s\n", tac.SignatureAlgo.Algorithm.String())
					}

					if len(tac.SerialNumber) > 0 {
						fmt.Printf("     Serial Number: %x\n", tac.SerialNumber)
					}

					if !tac.NotBefore.IsZero() {
						fmt.Printf("     Validity: %s to %s\n", tac.NotBefore.Format(time.RFC3339), tac.NotAfter.Format(time.RFC3339))
					}

					if len(tac.TimingAttrs) > 0 {
						fmt.Printf("     Timing Attributes: %d\n", len(tac.TimingAttrs))
						// Note: OID 1.3.6.1.4.1.601 is assigned to Bancomm (timing/GPS equipment vendor)
						// Sub-OIDs .10.4.1 and .10.4.2 contain timing quality metrics and policy
						for _, attr := range tac.TimingAttrs {
							oidStr := attr.Type.String()
							fmt.Printf("       - OID %s: %d value(s)\n", oidStr, len(attr.Values))

							// Try to parse known Bancomm OIDs
							if oidStr == "1.3.6.1.4.1.601.10.4.1" {
								// TimingMetrics
								for i, val := range attr.Values {
									tm, err := parseTimingMetrics(val)
									if err != nil {
										fmt.Printf("         [%d]: Error parsing timing metrics: %v\n", i, err)
										fmt.Printf("              Raw: %x (%d bytes)\n", val, len(val))
									} else {
										fmt.Printf("         [%d]: Timing Metrics\n", i)
										fmt.Printf("              NTPTime: %d.%d (sign: %d)\n", tm.NTPTime.Major, tm.NTPTime.Fractional, tm.NTPTime.Sign)
										fmt.Printf("              Offset: %d.%d (sign: %d)\n", tm.Offset.Major, tm.Offset.Fractional, tm.Offset.Sign)
										fmt.Printf("              Delay: %d.%d (sign: %d)\n", tm.Delay.Major, tm.Delay.Fractional, tm.Delay.Sign)
										fmt.Printf("              Expiration: %d.%d (sign: %d)\n", tm.Expiration.Major, tm.Expiration.Fractional, tm.Expiration.Sign)
										if len(tm.LeapEvents) > 0 {
											fmt.Printf("              Leap Events: %d\n", len(tm.LeapEvents))
											for j, le := range tm.LeapEvents {
												fmt.Printf("                [%d] LeapTime: %d.%d (sign: %d), Action: %d\n",
													j, le.LeapTime.Major, le.LeapTime.Fractional, le.LeapTime.Sign, le.Action)
											}
										}
									}
								}
							} else if oidStr == "1.3.6.1.4.1.601.10.4.2" {
								// TimingPolicy
								for i, val := range attr.Values {
									tp, err := parseTimingPolicy(val)
									if err != nil {
										fmt.Printf("         [%d]: Error parsing timing policy: %v\n", i, err)
										fmt.Printf("              Raw: %x (%d bytes)\n", val, len(val))
									} else {
										fmt.Printf("         [%d]: Timing Policy\n", i)
										fmt.Printf("              Policy IDs: %d\n", len(tp.PolicyIDs))
										for j, pid := range tp.PolicyIDs {
											fmt.Printf("                [%d] %s\n", j, pid.String())
										}
										if tp.MaxOffset != nil {
											fmt.Printf("              MaxOffset: %d.%d (sign: %d)\n", tp.MaxOffset.Major, tp.MaxOffset.Fractional, tp.MaxOffset.Sign)
										}
										if tp.MaxDelay != nil {
											fmt.Printf("              MaxDelay: %d.%d (sign: %d)\n", tp.MaxDelay.Major, tp.MaxDelay.Fractional, tp.MaxDelay.Sign)
										}
									}
								}
							} else {
								// Unknown OID - display raw hex
								for i, val := range attr.Values {
									if len(val) < 200 {
										fmt.Printf("         [%d]: %x (%d bytes)\n", i, val, len(val))
									} else {
										fmt.Printf("         [%d]: (%d bytes)\n", i, len(val))
									}
								}
							}
						}
					}

					if len(tac.Signature) > 0 {
						fmt.Printf("     Signature: %d bytes\n", len(tac.Signature))
					}
				}

			} else if unauthData.PeekASN1Tag(asn1.SET) {
				fmt.Printf("  -> Contains SET of attributes (properly formatted)\n")
				// Parse as attributes
				// ... could parse individual attributes here if needed
			} else {
				fmt.Printf("  -> Unknown structure in [1] tag\n")
			}
		} else {
			// Unknown tag - try to read it to report what it is
			var unknownData cryptobyte.String
			var unknownTag asn1.Tag

			// Try common tags
			for _, testTag := range []asn1.Tag{
				asn1.SEQUENCE,
				asn1.SET,
				asn1.INTEGER,
				asn1.OCTET_STRING,
				asn1.Tag(0).ContextSpecific().Constructed(),
				asn1.Tag(2).ContextSpecific().Constructed(),
			} {
				if s.PeekASN1Tag(testTag) {
					unknownTag = testTag
					break
				}
			}

			if unknownTag != 0 {
				fmt.Printf("Found unexpected tag: %v\n", unknownTag)
			} else {
				fmt.Printf("Found unknown/unrecognized tag\n")
			}

			// Try to skip this element
			if !s.ReadASN1(&unknownData, unknownTag) {
				return fmt.Errorf("failed to read unexpected data")
			}
			fmt.Printf("  Skipped %d bytes\n", len(unknownData))
		}
	}

	return nil
}
