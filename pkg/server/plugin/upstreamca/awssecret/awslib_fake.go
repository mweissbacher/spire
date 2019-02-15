package awssecret

import (
	"io/ioutil"
	"net/http"

	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
	"github.com/stretchr/testify/suite"
)

type fakeSecretsManagerClient struct {
	suite.Suite
	secretsmanageriface.SecretsManagerAPI

	mockStorage map[string]string
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
	resp.ARN = nil

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
		return retreq, &secretsmanager.GetSecretValueOutput{
			ARN:          input.SecretId,
			SecretString: &value,
		}
	} else {
		resp.ARN = nil
		return retreq, &resp
	}
}
