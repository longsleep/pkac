// Copyright 2014 Simon Eisenmann. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package pkac implements support for SPKAC/PKAC data as produced by the html
// <keygen> element (Signed Public Key And Challenge).
//
// References:
// - https://web.archive.org/web/20070401073244/http://wp.netscape.com/eng/security/comm4-keygen.html
// - https://wiki.openssl.org/index.php/Manual:Spkac(1)
// - http://lists.whatwg.org/pipermail/whatwg-whatwg.org/attachments/20080714/07ea5534/attachment.txt
package pkac

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
)

type pkacInfo struct {
	Raw       asn1.RawContent
	PublicKey publicKeyInfo
	Challenge string
}

type spkacInfo struct {
	Raw       asn1.RawContent
	Pkac      pkacInfo
	Algorithm pkix.AlgorithmIdentifier
	Signature asn1.BitString
}

func parseSpkac(derBytes []byte, validate bool) (pub crypto.PublicKey, err error) {
	var info spkacInfo
	if _, err = asn1.Unmarshal(derBytes, &info); err != nil {
		return
	}

	algo := getPublicKeyAlgorithmFromOID(info.Pkac.PublicKey.Algorithm.Algorithm)
	if algo == x509.UnknownPublicKeyAlgorithm {
		return nil, errors.New("x509: unknown public key algorithm")
	}

	pub, err = parsePublicKey(algo, &info.Pkac.PublicKey)
	if err != nil {
		return
	}

	sigAlgo := getSignatureDetailsFromOID(info.Algorithm.Algorithm)
	if sigAlgo == x509.UnknownSignatureAlgorithm {
		return nil, errors.New("x509: unknown signature algorithm")
	}

	if !validate {
		return
	}
	err = validateSignature(sigAlgo, pub, info.Pkac.Raw, info.Signature.Bytes)
	if err != nil {
		return
	}
	return
}

// ParseSPKAC parses a BER-encoded SPKAC and return the public key from it without
// validating a signature.
//
// This function is provided for compatibility with PKAC blobs using
// message digests that are known to be broken (e.g. RSA with MD2).
func ParseSPKAC(derBytes []byte) (crypto.PublicKey, error) {
	return parseSpkac(derBytes, false)
}

// ValidateSPKAC parses a BER-encoded SPKAC and return the public key from it,
// validating a signature to ensure integrity.
func ValidateSPKAC(derBytes []byte) (pub crypto.PublicKey, err error) {
	return parseSpkac(derBytes, true)
}
