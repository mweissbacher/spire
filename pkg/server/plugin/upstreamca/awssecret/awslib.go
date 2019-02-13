package awssecret

import (
	"io/ioutil"
	"net/http"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
	"github.com/stretchr/testify/suite"
)

type awsClient interface {
	DescribeInstancesWithContext(aws.Context, *ec2.DescribeInstancesInput, ...request.Option) (*ec2.DescribeInstancesOutput, error)
	GetInstanceProfileWithContext(aws.Context, *iam.GetInstanceProfileInput, ...request.Option) (*iam.GetInstanceProfileOutput, error)
}

type fakeSecretsManagerClient struct {
	suite.Suite
	secretsmanageriface.SecretsManagerAPI

	mockStorage map[string]string
}

func readARN(sm secretsmanageriface.SecretsManagerAPI, arn string) (*string, error) {

	req, resp := sm.GetSecretValueRequest(&secretsmanager.GetSecretValueInput{
		SecretId: aws.String(arn),
	})

	err := req.Send()
	if err != nil { // resp is now filled
		return nil, iidError.Wrap(err)
	}

	return resp.SecretString, nil

}

func newSecretsManagerClient(config *AWSSecretConfiguration, region string) (secretsmanageriface.SecretsManagerAPI, error) {
	conf := aws.NewConfig()
	conf.Region = aws.String(region)

	var awsSession *session.Session

	if config.SecretAccessKey != "" && config.AccessKeyID != "" {
		// Adding Token
		creds := credentials.NewStaticCredentials(config.AccessKeyID, config.SecretAccessKey, config.SecurityToken)
		awsSession = session.Must(session.NewSession(&aws.Config{Credentials: creds, Region: aws.String(region)}))
	} else {
		awsSession = session.Must(session.NewSession(&aws.Config{Region: aws.String(region)}))
	}

	svc := secretsmanager.New(awsSession)

	return svc, nil
}

func newFakeSecretsManagerClient() (secretsmanageriface.SecretsManagerAPI, error) {

	svc := new(fakeSecretsManagerClient)
	return svc, nil

}

func (sm *fakeSecretsManagerClient) GetSecretValueRequest(input *secretsmanager.GetSecretValueInput) (*request.Request, *secretsmanager.GetSecretValueOutput) {

	retreq := new(request.Request)
	httpReq, _ := http.NewRequest("POST", "", nil)

	retreq.HTTPRequest = httpReq

	resp := secretsmanager.GetSecretValueOutput{}

	cert, err := ioutil.ReadFile("_test_data/keys/cert.pem")
	if err != nil {
		return retreq, &resp
	}

	key, err := ioutil.ReadFile("_test_data/keys/private_key.pem")
	if err != nil {
		return retreq, &resp
	}

	sm.mockStorage = map[string]string{
		"cert": string(cert),
		"key":  string(key),
	}

	if value, ok := sm.mockStorage[*input.SecretId]; ok {
		resp := secretsmanager.GetSecretValueOutput{}
		resp.ARN = nil
		vstring := value
		resp.ARN = input.SecretId
		resp.SecretString = &vstring
		return retreq, &resp
	} else {
		resp.ARN = nil
		return retreq, &resp
	}
}
