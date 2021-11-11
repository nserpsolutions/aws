/**
 * @NApiVersion 2.1
 * @NScriptType Restlet
 * @NAmdConfig ./aws_config.json
 */

define(['N/file', './nse_aws'], (file, nseAws) => {
    const get = () => {
        return JSON.stringify(nseAws.s3Requests({
            awsRegion: 'eu-central-1',
            accountId: '',
            bucketName: 'nserp-s3',
            queueName: 'NSERPTestQueue',
            payload: null,
            secretKey: '',
            accessKey: '',
            message: '',
            action: 'PutObject',
            //objectKey: 'file.txt',
            fileObject: file.load({id: 10976})
        }));
    }
    return { get }
});
