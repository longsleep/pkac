// Copyright 2014 Simon Eisenmann. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package implements support for SPKAC/PKAC data as produced by the html
// <keygen> element (Signed Public Key And Challenge).
//
// References:
// - https://web.archive.org/web/20070401073244/http://wp.netscape.com/eng/security/comm4-keygen.html
// - https://www.openssl.org/docs/apps/spkac.html
// - http://lists.whatwg.org/pipermail/whatwg-whatwg.org/attachments/20080714/07ea5534/attachment.txt
package pkac

import (
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

func ParseSPKAC(derBytes []byte) (pub interface{}, err error) {

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

	return

}
