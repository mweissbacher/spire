package awssecret

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/upstreamca"
	"github.com/stretchr/testify/suite"
)

var (
	ctx = context.Background()
)

const (
	config = `{
	"ttl":"1h",
	"key_file_arn":"key",
	"cert_file_arn":"cert",
	"access_key_id":"keyid",
	"region":"us-west-2",
	"secret_access_key":"accesskey",
	"use_fake_secretsmanager":"yes"
}`
	trustDomain = "example.com"
)

func TestAWSSecret(t *testing.T) {
	suite.Run(t, new(fakeSecretsManagerClient))
}

func (sm *fakeSecretsManagerClient) TestConfigureNoGlobal() {
	a := New()
	req := new(spi.ConfigureRequest)
	resp, err := a.Configure(nil, req)
	sm.Require().NotNil(err)
	sm.Require().Nil(resp)

}
func (sm *fakeSecretsManagerClient) TestGetSecret() {

	svaluereq := secretsmanager.GetSecretValueInput{}
	secretid := aws.String("cert")
	svaluereq.SecretId = secretid
	req, resp := sm.GetSecretValueRequest(&svaluereq)
	sm.Require().NotNil(req)
	sm.Require().NotNil(resp)

	_ = req.Send()
	sm.Require().NotNil(aws.StringValue(resp.SecretString))
	sm.Require().True(strings.HasPrefix(aws.StringValue(resp.SecretString), "-----BEGIN CERTIFICATE-----"))
	sm.Require().NotNil(resp.ARN)

}

func (sm *fakeSecretsManagerClient) TestGetSecretFail() {

	svaluereq := secretsmanager.GetSecretValueInput{}
	secretid := aws.String("failure")
	svaluereq.SecretId = secretid
	req, resp := sm.GetSecretValueRequest(&svaluereq)
	sm.Require().NotNil(req)
	sm.Require().NotNil(resp)

	_ = req.Send()

	sm.Require().Nil(resp.SecretString)
	sm.Require().Nil(resp.ARN)

}

func (sm *fakeSecretsManagerClient) Test_SubmitValidCSR() {
	m, err := newWithDefault()
	sm.Require().Nil(err)

	const testDataDir = "_test_data/csr_valid"
	validCsrFiles, err := ioutil.ReadDir(testDataDir)
	sm.Require().NoError(err)

	for _, validCsrFile := range validCsrFiles {
		csrPEM, err := ioutil.ReadFile(filepath.Join(testDataDir, validCsrFile.Name()))
		sm.Require().NoError(err)
		block, rest := pem.Decode(csrPEM)
		sm.Require().Len(rest, 0)

		resp, err := m.SubmitCSR(ctx, &upstreamca.SubmitCSRRequest{Csr: block.Bytes})
		sm.Require().NoError(err)
		sm.Require().NotNil(resp)
	}
}
func (sm *fakeSecretsManagerClient) Test_SubmitInvalidCSR() {
	m, err := newWithDefault()
	sm.Require().Nil(err)

	const testDataDir = "_test_data/csr_invalid"
	validCsrFiles, err := ioutil.ReadDir(testDataDir)
	sm.Require().NoError(err)

	for _, validCsrFile := range validCsrFiles {
		csrPEM, err := ioutil.ReadFile(filepath.Join(testDataDir, validCsrFile.Name()))
		sm.Require().NoError(err)
		block, rest := pem.Decode(csrPEM)
		sm.Require().Len(rest, 0)

		resp, err := m.SubmitCSR(ctx, &upstreamca.SubmitCSRRequest{Csr: block.Bytes})
		sm.Require().Error(err)
		sm.Require().Nil(resp)
	}
}

func newWithDefault() (upstreamca.Plugin, error) {

	config := AWSSecretConfiguration{
		KeyFileARN:            "key",
		CertFileARN:           "cert",
		TTL:                   "1h",
		AccessKeyID:           "keyid",
		SecretAccessKey:       "accesskey",
		UseFakeSecretsManager: "yes",
	}

	jsonConfig, err := json.Marshal(config)
	pluginConfig := &spi.ConfigureRequest{
		Configuration: string(jsonConfig),
		GlobalConfig:  &spi.ConfigureRequest_GlobalConfig{TrustDomain: "localhost"},
	}

	m := New()
	_, err = m.Configure(ctx, pluginConfig)
	return m, err
}

func (sm *fakeSecretsManagerClient) TestFailConfiguration() {

	config := AWSSecretConfiguration{
		KeyFileARN:            "",
		CertFileARN:           "",
		TTL:                   "1h",
		AccessKeyID:           "keyid",
		Region:                "us-west-2",
		SecretAccessKey:       "accesskey",
		UseFakeSecretsManager: "yes",
	}

	jsonConfig, _ := json.Marshal(config)
	pluginConfig := &spi.ConfigureRequest{
		Configuration: string(jsonConfig),
		GlobalConfig:  &spi.ConfigureRequest_GlobalConfig{TrustDomain: "localhost"},
	}

	m := New()
	_, err := m.Configure(ctx, pluginConfig)
	sm.Require().Error(err)

}

func (sm *fakeSecretsManagerClient) TestAWSSecret_Configure() {
	pluginConfig := &spi.ConfigureRequest{
		Configuration: config,
		GlobalConfig:  &spi.ConfigureRequest_GlobalConfig{TrustDomain: trustDomain},
	}

	m := New()
	resp, err := m.Configure(ctx, pluginConfig)
	sm.Require().NoError(err)
	sm.Require().Equal(&spi.ConfigureResponse{}, resp)
}

func (sm *fakeSecretsManagerClient) TestAWSSecret_GetPluginInfo() {
	m, err := newWithDefault()
	sm.Require().NoError(err)
	res, err := m.GetPluginInfo(ctx, &spi.GetPluginInfoRequest{})
	sm.Require().NoError(err)
	sm.Require().NotNil(res)
}
