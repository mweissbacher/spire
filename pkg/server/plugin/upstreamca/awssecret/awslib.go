package awssecret

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
)

type awsClient interface {
	DescribeInstancesWithContext(aws.Context, *ec2.DescribeInstancesInput, ...request.Option) (*ec2.DescribeInstancesOutput, error)
	GetInstanceProfileWithContext(aws.Context, *iam.GetInstanceProfileInput, ...request.Option) (*iam.GetInstanceProfileOutput, error)
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
		creds := credentials.NewStaticCredentials(config.AccessKeyID, config.SecretAccessKey, config.SecurityToken)
		awsSession = session.Must(session.NewSession(&aws.Config{Credentials: creds, Region: aws.String(region)}))
	} else {
		awsSession = session.Must(session.NewSession(&aws.Config{Region: aws.String(region)}))
	}

	svc := secretsmanager.New(awsSession)

	return svc, nil
}
