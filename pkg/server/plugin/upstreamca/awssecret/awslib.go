package awssecret

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

// AWS Functions not specific to upstreamCA

func readARN(config *AWSSecretConfiguration, arn string) (*string, error) {

	sm, err := newSecretsManagerClient(config, "us-west-2")

	if err != nil {
		return nil, err
	}

	req, resp := sm.GetSecretValueRequest(&secretsmanager.GetSecretValueInput{
		SecretId: aws.String(arn),
	})

	err = req.Send()
	if err != nil { // resp is now filled
		return nil, iidError.Wrap(err)
	}

	return resp.SecretString, nil

}

func newSecretsManagerClient(config *AWSSecretConfiguration, region string) (*secretsmanager.SecretsManager, error) {
	conf := aws.NewConfig()
	conf.Credentials = credentials.NewStaticCredentials(config.AccessKeyID, config.SecretAccessKey, config.SecurityToken)
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
