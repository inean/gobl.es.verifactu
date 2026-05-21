package verifactu

import (
	"github.com/invopop/xmldsig"
)

func certificateFromDER(certificateDER, privateKeyDER []byte) (*xmldsig.Certificate, error) {
	return xmldsig.LoadCertificateFromDER(certificateDER, privateKeyDER)
}
