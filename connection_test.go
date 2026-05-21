package verifactu

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/invopop/gobl.verifactu/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewWithCertificateDERPreparesTLSConnection(t *testing.T) {
	certificateDER, privateKeyDER := testCertificateDER(t)

	c, err := New(
		Software{},
		WithCertificateDER(certificateDER, privateKeyDER),
	)

	require.NoError(t, err)
	require.NotNil(t, c.conn)
}

func TestNewWithCertificateDERSupportsSigning(t *testing.T) {
	certificateDER, privateKeyDER := testCertificateDER(t)

	c, err := New(
		Software{},
		WithCertificateDER(certificateDER, privateKeyDER),
		WithSigning(),
	)
	require.NoError(t, err)

	env := test.LoadEnvelope("inv-base.json")
	reg, err := c.RegisterInvoice(env, nil)

	require.NoError(t, err)
	require.NotNil(t, reg.Signature)
}

func TestNewWithCertificateDERRejectsInvalidPrivateKey(t *testing.T) {
	certificateDER, _ := testCertificateDER(t)

	c, err := New(
		Software{},
		WithCertificateDER(certificateDER, []byte("not-a-der-private-key")),
	)

	require.Error(t, err)
	assert.Nil(t, c)
	assert.True(t, strings.Contains(err.Error(), "private key DER is unsupported"))
}

func testCertificateDER(t *testing.T) ([]byte, []byte) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "gobl-verifactu-test",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
	}
	certificateDER, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&key.PublicKey,
		key,
	)
	require.NoError(t, err)

	privateKeyDER := x509.MarshalPKCS1PrivateKey(key)
	return certificateDER, privateKeyDER
}
