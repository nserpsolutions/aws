/**
 * @NApiVersion 2.1
 * @NScriptType Restlet
 * @NAmdConfig ./aws_config.json
 */

define(['N/file', './nse_aws'], (file, nseAws) => {
    const get = () => {
        return JSON.stringify(nseAws.secretsManagerRequests({
            awsRegion: 'eu-central-1',
            accountId: '',
            bucketName: 'nserp-s3',
            queueName: 'NSERPTestQueue',
            payload: null,
            secretKey: '',
            accessKey: '',
            message: '',
            secretId: 'nserp-secret',
            action: 'DescribeSecret',
            //objectKey: 'file.txt',
            fileObject: file.load({id: 10976})
        }));
    }
    return { get }
});
