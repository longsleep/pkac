// Copyright 2014 Simon Eisenmann. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkac

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path"
	"testing"
	"time"
)

// Generated using:
//   openssl genrsa -out privkey.pem 2048
//   openssl rsa -in privkey.pem -outform der | xxd -p -
var privateKeyHex = `308204a40201000282010100caff682f6d9939c1a8f0917eb0c210ab1b7f4d7ad33272c7a0f27160376dcc2922db8d4fc9b29bc2ae4ea394736cf1dd7e15c17253f007a9862263ad2648cca60deb67868fe2a96e6c4e1ce2c8e695990ec8ec933a2eaaf5b43df7efa553beaff528aac826b9f2084bb17b2b1f945a52fae4d8e57e585799fc0143d0863af46895e72002344abc8b77429e4866fea7bbb1966286ed0f26c65d707a5dd65c416bd6854b6bad411df6cef0886b015f1b501b1cd2d597fce49973ad757b15f55d9fdfdee8f145a2fdeb1ada37b012effccd234db8af8dbad633e7553a5d1707f609c9df53baf00a381c7b37c10dc215394962c947e1d504d1644612e0b51454700702030100010282010057fed931de0792d2d121df6014cd3b1e811ff0fd3239e729842a345d6a09ad7b9381aac31082dd244a1d0aa9da533a91320bca3c7e0849ba01cc3c7b1d62675c0022b050d36484dfba112e525c961ff9264090d4cd5ed77b04f3ebdb3546951d7f5f6e90aec0e21b187cca108a72eba896dbc6edcc940cfd5211564d3932ab29389973aaa2a7e9b1bd3bc5c36d34ee86b71f5c9613c91c677ce62ceb037e75d8bd831775ca675f6e038394332f7aa6f79f742bf2f7f2d03f57b51f5a1f4705f7027e2aedab2d87d0b1f7f62cb5e2522a052f0112330785fd9bbd6ee6ba86604f0fd088097d0c2240ef5c2c662fb2ccad77cf4e206b54ba9f17d38e82f7bca8d102818100f889755b4dfbcba3b0d4a966d1caed1dc1da1272ccc5a84dcd763c137c00e8af0adfb6d0e9b581e08cca5172337f294a005779f4d6fb0f36099e7cb1c7c814c0a1069176044ee39250566fb3881e5fa196309de507a90d3f65de9d22510b3144471636063b252351fee8950923beff3a2351cedd808f02b7f84affed3a0b03df02818100d117e19a050a6cee17b7177b859c0262b3270473d26ff86331ad93d2c52e4059ee192655cfa7ac1411b5658fe3aca643934c44c819a272ab3e427d0d0bced158c8e9dd617b6c1057a3bbc8e1ade3e5b51ac080c2a5a11971349d7dea02cb510700dd896d0a205f54cb1c8a3ec6ae230f7ca0c0f4bed18189de2e0b585186d8d902818100b376b67a4eae62167a0aa5a42c1b26eb14de7df1cd71709d759e49b51c169fee3da0db26b18bb213ce360d67b44dbf27c3656717e7e073d4664fbde4b5c9014b333b45effd1e65ef71f96841302a168ddca090731ffbef27f74c2f14e7867875c00b06c9ab0d9f1a8741b4d45bae80279ff763b3c82ffc1b91bbbe5fb348deeb02818100aa084f8f5e36022b03e2021892a831506dfb76a5712558c9e16613e5bc2f46695b33dc76bfaccc446dba236305742aa89d29d26d1e5b7a00435af2321fbe0983b7ae66369595651cbfab3f4a368c330a393cfdf84b945c0a310d398d88c4299a165c111b38b6e68f1fb48fbf48f5e6d0fb3a066f8095025048fb0c82bf9976d102818005cfd9728070709f0d089e9b4b3615a62ac5164e14301a927420d66a26d510cda862c5afad233578cda8432bcbcc3b03623a30ff3fabd7cd163d4000064ec5f368cf12a4ae9ae57cf73d84ce81479aa6d413a350bd228f707eba55afc969647cbcfaddbfff63aae23dbb9de57fc33b9c0912720e44281c9a6a6fa1302ed7a4bc`

// Generated using:
//	 openssl req -new -key privkey.pem -out cert.csr
//   openssl x509 -req -days 365 -in cert.csr -signkey privkey.pem -out cert.crt
//   openssl x509 -in cert.crt -outform DER | xxd -p -
var certificateHex = `30820306308201ee020900b303875786d02b7b300d06092a864886f70d01010b05003045310b30090603550406130241553113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c7464301e170d3134303530313137323035325a170d3135303530313137323035325a3045310b30090603550406130241553113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c746430820122300d06092a864886f70d01010105000382010f003082010a0282010100caff682f6d9939c1a8f0917eb0c210ab1b7f4d7ad33272c7a0f27160376dcc2922db8d4fc9b29bc2ae4ea394736cf1dd7e15c17253f007a9862263ad2648cca60deb67868fe2a96e6c4e1ce2c8e695990ec8ec933a2eaaf5b43df7efa553beaff528aac826b9f2084bb17b2b1f945a52fae4d8e57e585799fc0143d0863af46895e72002344abc8b77429e4866fea7bbb1966286ed0f26c65d707a5dd65c416bd6854b6bad411df6cef0886b015f1b501b1cd2d597fce49973ad757b15f55d9fdfdee8f145a2fdeb1ada37b012effccd234db8af8dbad633e7553a5d1707f609c9df53baf00a381c7b37c10dc215394962c947e1d504d1644612e0b5145470070203010001300d06092a864886f70d01010b05000382010100332e41ee0c256fbf0f5d301420423fa2f83b0a52f584e46a1661f1b4b28613675c83ebf5028ee43f1582c778478f50ded6150c103b312b927e94e8e5fbd70a6202f1493bc4c0eea81e46f2ffb5d7de71b4310a239f42ea4599c904248ac6d28c28becdc118d58600b8e400f46e321cbab1ceeb1403214b63301f5d4c4a373867603f30bf4ef2fbbc5be887c4f19a54c649cd44c11c4ffe7ab1712246fc02929e6e59b399c8654c8b34012bb9dcfba9fa9dc4768040dc82abb2bb5d289bee9d120cb1b1369b2d1c1597391d6efc7528d65c82bed8e732477f93f13b502c4715ddf42880a825ab08ed9a89265d6cacf7c775802559cf65b0b6d74e0f8f241fb656`

// Generated using:
//   openssl spkac -key privkey.pem -challenge hello -out spkac.cnf
var spkacRSABase64 = `MIICRTCCAS0wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDK/2gvbZk5wajwkX6wwhCrG39NetMycseg8nFgN23MKSLbjU/JspvCrk6jlHNs8d1+FcFyU/AHqYYiY60mSMymDetnho/iqW5sThziyOaVmQ7I7JM6Lqr1tD3376VTvq/1KKrIJrnyCEuxeysflFpS+uTY5X5YV5n8AUPQhjr0aJXnIAI0SryLd0KeSGb+p7uxlmKG7Q8mxl1wel3WXEFr1oVLa61BHfbO8IhrAV8bUBsc0tWX/OSZc611exX1XZ/f3ujxRaL96xraN7AS7/zNI024r4261jPnVTpdFwf2CcnfU7rwCjgcezfBDcIVOUliyUfh1QTRZEYS4LUUVHAHAgMBAAEWBWhlbGxvMA0GCSqGSIb3DQEBBAUAA4IBAQCIBcbE+nw/vpjLvdl7EVnX4TWpKxDej92MOafyaOjNmy/iVhto57Lr+jBhm0A1oHpmGXLarkQPSLcXndZJFm/WSdHZ5pids+fEpe9yyMhgYYkVqqNbnGQmgSrmRZjIbzF6J69SaYXqJ1jQAZ4RrxRsgimfUfGw3C59yytdqkqllg2ojZe158vRlO/X6ysyCevchT9InDAWXE8YM/LBaI6jSlAz1BUFw0phpnAWTpULjMoP45QelY26gfNT1oDD+7PXAiEeo101kba67UcKXr8/7Z05iUONvkE+X1nNLynpvSskz7hha0pjtR+ipDVL9vIQxBFZ1xwrbbOj1fmIKzaE`

func TestParseSPKAC(t *testing.T) {
	derBytes, _ := base64.StdEncoding.DecodeString(spkacRSABase64)
	if _, err := ParseSPKAC(derBytes); err != nil {
		t.Error("failed to parse SPKAC: %s", err)
	}
}

func TestCreateCertificateFromSPKAC(t *testing.T) {

	parentDerBytes, _ := hex.DecodeString(certificateHex)
	parent, err := x509.ParseCertificates(parentDerBytes)
	if err != nil {
		t.Error("failed to parse builtin certificate: %s", err)
	}

	privateKeyDerBytes, _ := hex.DecodeString(privateKeyHex)
	private, err := x509.ParsePKCS1PrivateKey(privateKeyDerBytes)
	if err != nil {
		t.Error("failed to parse builtin private key: %s", err)
	}

	spkacDerBytes, _ := base64.StdEncoding.DecodeString(spkacRSABase64)
	public, err := ParseSPKAC(spkacDerBytes)
	if err != nil {
		t.Error("failed to parse SPKAC: %s", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour * 365)
	// Used from template:
	//   SerialNumber, Subject, NotBefore, NotAfter, KeyUsage, ExtKeyUsage,
	//   UnknownExtKeyUsage, BasicConstraintsValid, IsCA, MaxPathLen,
	//   SubjectKeyId, DNSNames, PermittedDNSDomainsCritical,
	//   PermittedDNSDomains.
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "Testing"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certDerBytes, err := x509.CreateCertificate(rand.Reader, template, parent[0], public, private)
	if err != nil {
		t.Error("failed to create certificate: %s", err)
	}

	certOut, err := os.Create(path.Join("test", "42.pem"))
	if err != nil {
		t.Error("failed to open test/test.pem for writing: %s", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDerBytes})
	certOut.Close()

}
