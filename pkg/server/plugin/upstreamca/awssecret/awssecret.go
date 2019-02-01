package awssecret

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/hashicorp/hcl"
	"github.com/zeebo/errs"

	"github.com/spiffe/spire/pkg/common/x509svid"
	"github.com/spiffe/spire/pkg/common/x509util"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/upstreamca"
)

const (
	pluginName = "aws_secrets"
)

var (
	iidError = errs.Class("aws-iid")
)

type AWSSecretConfiguration struct {
	TTL             string `hcl:"ttl" json:"ttl"` // time to live for generated certs
	CertFileARN     string `hcl:"cert_file_arn" json:"cert_file_arn"`
	KeyFileARN      string `hcl:"key_file_arn" json:"key_file_arn"`
	AccessKeyID     string `hcl:"access_key_id"`
	SecretAccessKey string `hcl:"secret_access_key"`
	SecurityToken   string `hcl:"secret_token"`
}

type awssecretPlugin struct {
	serialNumber x509util.SerialNumber

	mtx        sync.RWMutex
	cert       *x509.Certificate
	upstreamCA *x509svid.UpstreamCA

	mu     sync.RWMutex
	config *AWSSecretConfiguration
	//clients map[string]awsClient

	hooks struct {
		getenv    func(string) string
		newClient func(config *AWSSecretConfiguration, region string) (*secretsmanager.SecretsManager, error)
	}
}

type awsClient interface {
	DescribeInstancesWithContext(aws.Context, *ec2.DescribeInstancesInput, ...request.Option) (*ec2.DescribeInstancesOutput, error)
	GetInstanceProfileWithContext(aws.Context, *iam.GetInstanceProfileInput, ...request.Option) (*iam.GetInstanceProfileOutput, error)
	GetIAM() *iam.IAM
	GetEC2() *ec2.EC2
}

func (m *awssecretPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	// Parse HCL config payload into config struct

	config := new(AWSSecretConfiguration)

	if err := hcl.Decode(&config, req.Configuration); err != nil {
		return nil, err
	}

	if req.GlobalConfig == nil {
		return nil, errors.New("global configuration is required")
	}

	if req.GlobalConfig.TrustDomain == "" {
		return nil, errors.New("trust_domain is required")
	}

	// Set defaults from the environment
	if config.AccessKeyID == "" {
		config.AccessKeyID = m.hooks.getenv("AWS_ACCESS_KEY_ID")
	}
	if config.SecretAccessKey == "" {
		config.SecretAccessKey = m.hooks.getenv("AWS_SECRET_ACCESS_KEY")
	}

	if config.SecurityToken == "" {
		config.SecurityToken = m.hooks.getenv("AWS_SESSION_TOKEN")
	}

	switch {
	case config.AccessKeyID != "" && config.SecretAccessKey != "":
	case config.AccessKeyID != "" && config.SecretAccessKey == "":
		return nil, iidError.New("configuration missing secret access key")
	case config.AccessKeyID == "" && config.SecretAccessKey != "":
		return nil, iidError.New("configuration missing access key id")
	case config.AccessKeyID == "" && config.SecretAccessKey == "":
		return nil, iidError.New("configuration missing both access key id and secret access key")
	}

	// set the AWS configuration and reset clients
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config = config

	keyPEMstr, err := readARN(config, config.KeyFileARN)

	if err != nil {
		return nil, fmt.Errorf("unable to read %s: %s", config.KeyFileARN, err)
	}

	keyPEM := []byte(*keyPEMstr)

	block, rest := pem.Decode(keyPEM)

	if block == nil {
		return nil, errors.New("invalid key format")
	}

	if len(rest) > 0 {
		return nil, errors.New("invalid key format: too many keys")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	certPEMstr, err := readARN(config, config.CertFileARN)

	if err != nil {
		return nil, fmt.Errorf("unable to read %s: %s", config.CertFileARN, err)
	}

	certPEM := []byte(*certPEMstr)

	block, rest = pem.Decode(certPEM)

	if block == nil {
		return nil, errors.New("invalid cert format")
	}

	if len(rest) > 0 {
		return nil, errors.New("invalid cert format: too many certs")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	ttl, err := time.ParseDuration(config.TTL)
	if err != nil {
		return nil, fmt.Errorf("invalid TTL value: %v", err)
	}

	// Set local vars from config struct
	m.mtx.Lock()
	defer m.mtx.Unlock()

	m.cert = cert
	m.upstreamCA = x509svid.NewUpstreamCA(
		x509util.NewMemoryKeypair(cert, key),
		req.GlobalConfig.TrustDomain,
		x509svid.UpstreamCAOptions{
			SerialNumber: m.serialNumber,
			TTL:          ttl,
		})

	return &spi.ConfigureResponse{}, nil
}

func (*awssecretPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (m *awssecretPlugin) SubmitCSR(ctx context.Context, request *upstreamca.SubmitCSRRequest) (*upstreamca.SubmitCSRResponse, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	if m.upstreamCA == nil {
		return nil, errors.New("invalid state: not configured")
	}

	cert, err := m.upstreamCA.SignCSR(ctx, request.Csr)
	if err != nil {
		return nil, err
	}

	return &upstreamca.SubmitCSRResponse{
		Cert:                cert.Raw,
		UpstreamTrustBundle: m.cert.Raw,
	}, nil
}

func New() upstreamca.Plugin {
	p := &awssecretPlugin{}
	p.hooks.getenv = os.Getenv
	p.hooks.newClient = newSecretsManagerClient
	p.serialNumber = x509util.NewSerialNumber()

	return p
}
