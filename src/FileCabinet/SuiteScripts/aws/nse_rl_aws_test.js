/**
 * @NApiVersion 2.1
 * @NScriptType Restlet
 * @NAmdConfig ./aws_config.json
 */

 define(['N/file', './nse_aws'], (file, nseAws) => {
    const get = () => {
        const stsAssumeRoleResponse = nseAws.stsRequests({
            awsRegion: 'eu-central-1',
            payload: null,
            secretKey: '',
            accessKey: '',
            action: 'AssumeRole',
            roleArn: 'arn:aws:iam::012345678912:role/nserp-admin-role',
            roleSessionName: 'nserp-assume-test',
            duration: 900
        });

        if (stsAssumeRoleResponse.code === 200) {
            const assumeRoleResult = JSON.parse(stsAssumeRoleResponse.body).AssumeRoleResponse.AssumeRoleResult;

            return JSON.stringify(nseAws.s3Requests({
                awsRegion: 'eu-central-1',
                bucketName: 'nserp-s3',
                queueName: 'NSERPTestQueue',
                payload: null,
                secretKey: assumeRoleResult.Credentials.SecretAccessKey,
                accessKey: assumeRoleResult.Credentials.AccessKeyId,
                sessionToken: assumeRoleResult.Credentials.SessionToken,
                action: 'PutObject',
                fileObject: file.load({id: 10976})
            }));
        }
        

        return JSON.stringify(nseAws.secretsManagerRequests({
            awsRegion: 'eu-central-1',
            payload: null,
            secretKey: '',
            accessKey: '',
            secretId: 'nserp-secret',
            action: 'DescribeSecret'
        }));
    }
    return { get }
});
