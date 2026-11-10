package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	verifactu "github.com/invopop/gobl.es.verifactu"
	"github.com/invopop/gobl.es.verifactu/test"
	"github.com/stretchr/testify/require"
	"software.sslmate.com/src/go-pkcs12"
)

func TestGatewaySubmission(t *testing.T) {
	requestSchema, err := test.LoadSchema("main.xsd")
	require.NoError(t, err)
	t.Cleanup(requestSchema.Free)
	responseSchema, err := test.LoadSchema("RespuestaSuministro.xsd")
	require.NoError(t, err)
	t.Cleanup(responseSchema.Free)
	setSoftwareEnvironment(t)
	t.Setenv(envLaneWorkerOperationID, "plz_fiscalization_job_soap")
	t.Setenv(envAeatOperationType, operationTypeRegister)
	t.Setenv(envLaneWorkerExecutionMode, executionModeSend)
	t.Setenv(envAeatPreviousChainDataJSON, "")
	t.Setenv(envAuthorityTimeoutSeconds, "0")
	p12, err := os.ReadFile(test.Path("test", "certs", "test.p12"))
	require.NoError(t, err)
	key, cert, _, err := pkcs12.DecodeChain(p12, "test")
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.der"), filepath.Join(dir, "key.der")
	require.NoError(t, os.WriteFile(certPath, cert.Raw, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyDER, 0o600))
	t.Setenv("CERTIFICATE_PATH", "")
	t.Setenv("CERTIFICATE_DER_PATH", certPath)
	t.Setenv("CERTIFICATE_PRIVATE_KEY_DER_PATH", keyPath)
	stdin := mustReadFile(t, test.Path("test", "data", "inv-simplified.json"))
	clock := time.Date(2024, 11, 26, 4, 0, 0, 0, time.UTC)

	for _, scenario := range []struct {
		name, submission, line, code, duplicate string
		state, errorCode                        string
		timeout                                 bool
	}{
		{name: "accepted", submission: "Correcto", line: "Correcto", state: "REGISTERED"},
		{name: "accepted with errors", submission: "ParcialmenteCorrecto", line: "AceptadoConErrores", code: "2000", state: "REGISTERED"},
		{name: "rejected", submission: "Incorrecto", line: "Incorrecto", code: "3001", state: "INVALID", errorCode: "3001"},
		{name: "timeout then duplicate", submission: "Incorrecto", line: "Incorrecto", code: "3000", duplicate: "Correcta", state: "REQUIRES_INSPECTION", errorCode: "duplicate_unverified", timeout: true},
		{name: "cancelled duplicate", submission: "Incorrecto", line: "Incorrecto", code: "3000", duplicate: "Anulada", state: "REQUIRES_INSPECTION", errorCode: "duplicate_cancelled"},
		{name: "accepted with errors duplicate", submission: "Incorrecto", line: "Incorrecto", code: "3000", duplicate: "AceptadaConErrores", state: "REQUIRES_INSPECTION", errorCode: "duplicate_unverified"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			payload := soapInvoiceReply(scenario.submission, scenario.line, scenario.code, scenario.duplicate)
			require.Empty(t, test.ValidateXML(responseSchema, []byte(payload)))
			soap := `<soap:Envelope xmlns:soap="` + verifactu.EnvNamespace + `"><soap:Body>` + payload + `</soap:Body></soap:Envelope>`
			var fingerprints []string
			send := func(_ *verifactu.Client, _ context.Context, request *verifactu.InvoiceRequest) (*verifactu.InvoiceResponse, error) {
				body, err := request.Envelop().Bytes()
				require.NoError(t, err)
				require.Empty(t, test.ValidateXML(requestSchema, body))
				require.Contains(t, string(body), "<sum1:TipoFactura>F2</sum1:TipoFactura>")
				require.Contains(t, string(body), "<sum1:NumSerieFactura>SAMPLE-004</sum1:NumSerieFactura>")
				fingerprints = append(fingerprints, request.Lines[0].ChainData().Fingerprint)
				if scenario.timeout && len(fingerprints) == 1 {
					return nil, context.DeadlineExceeded
				}
				var response verifactu.EnvelopeResponse
				require.NoError(t, xml.Unmarshal([]byte(soap), &response))
				return response.Body.InvoiceResponse, nil
			}
			submit := func(at time.Time) map[string]any {
				options := gateway(root(), verifactu.WithCurrentTime(at))
				options.sendInvoice = send
				command := options.cmd()
				command.SetIn(strings.NewReader(stdin))
				var stdout bytes.Buffer
				command.SetOut(&stdout)
				require.NoError(t, command.ExecuteContext(context.Background()))
				return decodeLaneWorkerResult(t, stdout.String())
			}
			if scenario.timeout {
				timeout := submit(clock)
				require.Equal(t, "LANE_WORKER_JOB_PENDING", laneWorkerResultHeadPayload(t, timeout)["status"])
				require.Equal(t, "authority_timeout", laneWorkerResultError(t, timeout)["code"])
				require.NotNil(t, timeout["retry"])
			}
			result := submit(clock.Add(time.Minute))
			if scenario.timeout {
				require.Len(t, fingerprints, 2)
				require.NotEqual(t, fingerprints[0], fingerprints[1])
			} else {
				require.Len(t, fingerprints, 1)
			}
			require.Equal(t, scenario.state, laneWorkerResultHeadPayload(t, result)["status"])
			require.Nil(t, result["retry"])
			if scenario.errorCode == "" {
				require.Nil(t, result["error"])
				chain := result["chain"].(map[string]any)
				require.Equal(t, "https://prewww2.aeat.es/wlpl/TIKE-CONT/ValidarQR?nif=B85905495&numserie=SAMPLE-004&fecha=13-11-2024&importe=2178.00", chain["qr_payload"])
			} else {
				require.Equal(t, scenario.errorCode, laneWorkerResultError(t, result)["code"])
				require.Equal(t, "adapter_rejected", laneWorkerResultError(t, result)["category"])
				require.Nil(t, result["chain"])
			}
			artifact := result["artifacts"].([]any)[0].(map[string]any)
			require.Contains(t, decodedPrivateEvidence(t, artifact), scenario.line)
			if scenario.duplicate != "" {
				require.Equal(t, scenario.duplicate, artifact["contents"].(map[string]any)["duplicate_state"])
			}
			assertNoRawAuthorityLeakage(t, result)
		})
	}
}

// AEAT web service specification, sections 6.4.4 and 6.5.2. The response
// echoes the public F2 invoice example and uses synthetic response metadata.
func soapInvoiceReply(submission, line, code, duplicate string) string {
	const responseNS = "https://www2.agenciatributaria.gob.es/static_files/common/internet/dep/aplicaciones/es/aeat/tike/cont/ws/RespuestaSuministro.xsd"
	errorXML := ""
	if code != "" {
		errorXML = "<CodigoErrorRegistro>" + code + "</CodigoErrorRegistro>"
	}
	if duplicate != "" {
		errorXML += `<RegistroDuplicado><sf:IdPeticionRegistroDuplicado>fixture-original</sf:IdPeticionRegistroDuplicado><sf:EstadoRegistroDuplicado>` + duplicate + `</sf:EstadoRegistroDuplicado></RegistroDuplicado>`
	}
	return fmt.Sprintf(`<RespuestaRegFactuSistemaFacturacion xmlns="%s" xmlns:sf="%s">
  <Cabecera><sf:ObligadoEmision><sf:NombreRazon>Invopop S.L.</sf:NombreRazon><sf:NIF>B85905495</sf:NIF></sf:ObligadoEmision></Cabecera>
  <TiempoEsperaEnvio>60</TiempoEsperaEnvio>
  <EstadoEnvio>%s</EstadoEnvio>
  <RespuestaLinea>
    <IDFactura><sf:IDEmisorFactura>B85905495</sf:IDEmisorFactura><sf:NumSerieFactura>SAMPLE-004</sf:NumSerieFactura><sf:FechaExpedicionFactura>13-11-2024</sf:FechaExpedicionFactura></IDFactura>
    <Operacion><sf:TipoOperacion>Alta</sf:TipoOperacion></Operacion>
    <EstadoRegistro>%s</EstadoRegistro>%s
  </RespuestaLinea>
</RespuestaRegFactuSistemaFacturacion>`, responseNS, verifactu.SUM1, submission, line, errorXML)
}
