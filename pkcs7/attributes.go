package pkcs7

import (
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

func (a *Attributes) Marshal() []byte {
	b := cryptobyte.NewBuilder(nil)
	// Attributes := SET OF Attribute
	b.AddASN1(asn1.SET, func(b *cryptobyte.Builder) {
		// Add the content type
		b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(OIDAttributeContentType)
			b.AddASN1(asn1.SET, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(a.ContentType)
			})
		})
		if !a.SigningTime.IsZero() {
			b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(OIDAttributeSigningTime)
				b.AddASN1(asn1.SET, func(b *cryptobyte.Builder) {
					b.AddASN1UTCTime(a.SigningTime)
				})
			})
		}
		// Digest from Authenticode
		b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(OIDAttributeMessageDigest)
			b.AddASN1(asn1.SET, func(b *cryptobyte.Builder) {
				b.AddASN1OctetString(a.MessageDigest)
			})
		})
		for _, attr := range a.Other {
			b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(attr.Type)
				b.AddASN1(asn1.SET, func(b *cryptobyte.Builder) {
					b.AddBytes(attr.Bytes)
				})
			})
		}
	})
	return b.BytesOrPanic()
}
