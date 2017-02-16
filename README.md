# pkac [![Build Status](https://travis-ci.org/longsleep/pkac.svg)](https://travis-ci.org/longsleep/pkac)  [![GoDoc](https://godoc.org/github.com/longsleep/pkac?status.svg)](https://godoc.org/github.com/longsleep/pkac)

Pkac implements Go support for SPKAC/PKAC data as produced by the html [&lt;keygen&gt;](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/keygen) element.

PKAC is short for `Public Key and Challenge` and was defined a very long time ago with the Netscape browser as [Signed Public Key And Challenge](https://web.archive.org/web/20070401073244/http://wp.netscape.com/eng/security/comm4-keygen.html).

This package implements PKAC parsing and SPKAC validation from ASN.1-encoded
[]byte slices. For usage examples, see `pkac_test.go`.

## Installation

```text
go get github.com/longsleep/pkac
```
