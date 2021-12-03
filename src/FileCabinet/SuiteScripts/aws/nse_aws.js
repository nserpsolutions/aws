/**
 * @NApiVersion 2.1
 * @NAmdConfig ./aws_config.json
 * 
 * @link https://gist.github.com/drudge/01f204a6fe30e3f2477bf7834297414f Created based on the solution published here
 */


 define(['N/file', 'N/https', 'N/crypto', 'CryptoJS', 'SHA256', 'HMAC', 'Base64'], (file, https, crypto, CryptoJS) => {
    /**
     * @typedef {object} AwsUrl
     * @property {string} host
     * @property {string} canonicalUri
     * @property {string} canonicalQueryString
     */

    /**
     * @typedef {object} https.ServerResponse
     * @property 
     */

    /**
     * @typedef {object} file.File
     * @property 
     */

    const AWS_DOMAIN = 'amazonaws.com';
    const HASH_ALGORITHM = 'AWS4-HMAC-SHA256'

    /**
     * Generates AWS Date string
     * 
     * @returns {string} AWS Date string
     */
    const getXAmzDate = () => {
        return new Date().toISOString().replace(/[-:]|.[^.Z]+(?=Z)/g, '');
    }

    /**
     * Encodes URI component
     * 
     * @param {string} str String to be encoded
     * @returns {string} Encoded string
     */
    const rfc3986EncodeURIComponent = (str) => {
        return encodeURIComponent(str).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16)}`);
    }

    /**
     * Generates URL object for the AWS service being connected.
     * 
     * @param {object} options Details of the AWS Service being connected to
     * @param {string} options.awsService Name of the AWS Service being connected (e.g. s3, sqs)
     * @param {string} options.awsRegion AWS Region
     * @param {string} options.accountId AWS Account ID
     * @param {string} options.queueName SQS Queue Name
     * @param {string} options.bucketName S3 Bucket Name
     * @param {string} options.folderPath S3 Folder Path
     * @param {string} options.objectKey S3 Object Key
     * @param {{string, string}[]} options.requestParams 
     * @returns {AwsUrl} AwsUrl object
     */
    const generateAwsUrl = (options) => {
        let returnData = {
            host: '',
            canonicalUri: '',
            canonicalQueryString: ''
        };

        switch (options.awsService) {
            case 'sqs': 
                returnData.host = `${options.awsService}.${options.awsRegion}.${AWS_DOMAIN}`;
                returnData.canonicalUri = options.accountId ? `/${options.accountId}/${options.queueName}` : `/${options.queueName}`;
                break;
            case 's3': 
                returnData.host = `${options.bucketName}.${options.awsService}.${options.awsRegion}.${AWS_DOMAIN}`;
                returnData.canonicalUri = `/${options.folderPath ? options.folderPath : ''}${options.objectKey ? options.objectKey : ''}`;
                break;
            case 'secretsmanager':
                returnData.host = `${options.awsService}.${options.awsRegion}.${AWS_DOMAIN}`;
                returnData.canonicalUri = `/`;
                break;
            case 'sts':
                returnData.host = `${options.awsService}.${options.awsRegion}.${AWS_DOMAIN}`;
                returnData.canonicalUri = `/`;
                break;
        }


        options.requestParams.sort((a, b) => a.name > b.name ? 1 : -1);
        options.requestParams.forEach(({name, value}) => {
            returnData.canonicalQueryString += `${returnData.canonicalQueryString === '' ? '' : '&'}${encodeURIComponent(name)}=${name === 'MessageBody' ? rfc3986EncodeURIComponent(value) : encodeURIComponent(value)}`;
        });

        return returnData;
    }

    /**
     * Generates Hash for the payload and creates signed Authorization Header
     * 
     * @param {object} options Details of the AWS Headers and content
     * @param {string} options.payload Payload data
     * @param {object} options.requestHeaders Request headers that needs to be signed
     * @param {string} options.httpMethod HTTP Method
     * @param {AwsUrl} options.awsUrl AwsUrl object
     * @param {string} options.xAmzDate AWS Date string
     * @param {string} options.accessKey Access Key of the AWS user
     * @param {string} options.secretKey SecretKey of the AWS user
     * @param {string} options.awsRegion AWS Region
     * @param {string} options.awsService Name of the AWS Service being connected (e.g. s3, sqs)
     * @returns {string} Authorization header
     */
    const createAuthorizationHeader = (options) => {
        let payloadHash = crypto.createHash({
            algorithm: crypto.HashAlg.SHA256
        });

        if(options.payload) {
            payloadHash.update({
                input: options.payload
            });
        }
        options.requestHeaders['x-amz-content-sha256'] = payloadHash.digest().toLowerCase();
        const requestHeaderKeys = Object.keys(options.requestHeaders).sort((a, b) => a.toLowerCase() > b.toLowerCase() ? 1 : -1);
        const signedHeaders = requestHeaderKeys.join(';').toLowerCase();

        let canonicalHeaders = '';
        for (let key of requestHeaderKeys) {
            canonicalHeaders += (key.toLowerCase() + ':' + options.requestHeaders[key] + '\n');
            key !== key.toLowerCase() ? options.requestHeaders[key.toLowerCase()] = options.requestHeaders[key] : null;
        }

        let canonicalHash = crypto.createHash({
            algorithm: crypto.HashAlg.SHA256
        });
        canonicalHash.update({
            input: options.httpMethod + '\n' + options.awsUrl.canonicalUri + '\n' + options.awsUrl.canonicalQueryString + '\n' + canonicalHeaders + '\n' + signedHeaders + '\n' + options.requestHeaders['x-amz-content-sha256']
        });

        const dateKey = CryptoJS.HmacSHA256(options.xAmzDate.split('T')[0], `AWS4${options.secretKey}`);
        const dateRegionKey = CryptoJS.HmacSHA256(options.awsRegion, dateKey);
        const dateRegionServiceKey = CryptoJS.HmacSHA256(options.awsService, dateRegionKey);
        const credentialScope = `${options.xAmzDate.split('T')[0]}/${options.awsRegion}/${options.awsService}/aws4_request`;
        const signingKey = CryptoJS.HmacSHA256('aws4_request', dateRegionServiceKey);
        const signature = CryptoJS.HmacSHA256(HASH_ALGORITHM + '\n' + options.xAmzDate + '\n' + credentialScope + '\n' + canonicalHash.digest().toLowerCase(), signingKey);

        return `${HASH_ALGORITHM} Credential=${options.accessKey}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
    }

    /**
     * Sends request to AWS SQS API
     * 
     * @param {object} options Details of the SQS request
     * @param {string} options.queueName SQS Queue Name
     * @param {string} options.action SQS API Action
     * @param {object} options.message MessageBody for SendMessage. ReceiptHandle for DeleteMessage.
     * @param {string} options.httpMethod HTTP Method
     * @param {string} options.awsRegion AWS Region
     * @param {string} options.accountId AWS Account ID
     * @param {string} options.payload Payload required to calculate Hash
     * @param {string} options.accessKey Access Key of the AWS user or from the STS request
     * @param {string} options.secretKey SecretKey of the AWS user or from the STS request
     * @param {string} options.sessionToken Token received from STS request
     * @returns {https.ServerResponse} Response of the SQS request
     */
    const sqsRequests = (options) => {
        const SERVICE_NAME = 'sqs';
        const HTTP_METHOD = 'GET';
        let requestParams = [
            {name: 'Action', value: options.action},
            {name: 'Version', value: '2012-11-05'}
        ];
        let requestHeaders = {};
        if (options.sessionToken) {
            requestHeaders['X-Amz-Security-Token'] = options.sessionToken;
        }

        switch (options.action) {
            case 'ReceiveMessage':
                break;
            case 'SendMessage': 
                requestParams.push({name: 'MessageBody', value: options.message});
                break;
            case 'DeleteMessage': 
                requestParams.push({name: 'ReceiptHandle', value: options.message});
                break;
            case 'GetQueueAttributes' : 
                requestParams.push({name: 'AttributeName.1', value: 'All'});
                break;
        }

        const awsUrl = generateAwsUrl({
            awsService: SERVICE_NAME,
            awsRegion: options.awsRegion,
            accountId: options.accountId,
            queueName: options.queueName,
            requestParams: requestParams
        });
        const xAmzDate = getXAmzDate();

        requestHeaders['host'] = awsUrl.host;
        requestHeaders['x-amz-date'] = xAmzDate
        requestHeaders['Authorization'] = createAuthorizationHeader({
            payload: options.payload,
            awsUrl: awsUrl,
            xAmzDate: xAmzDate,
            awsRegion: options.awsRegion,
            awsService: SERVICE_NAME,
            httpMethod: HTTP_METHOD,
            secretKey: options.secretKey,
            accessKey: options.accessKey,
            requestHeaders: requestHeaders
        });
        requestHeaders['Accept'] = 'application/json';

        return https.get({
            url: `https://${awsUrl.host}${awsUrl.canonicalUri}?${awsUrl.canonicalQueryString}`,
            headers: requestHeaders
        });
    }

    /**
     * Sends request to AWS S3 API. PutObject supports text files only because AWS does not convert base64 to binary after receiving data.
     * 
     * @param {object} options Details of the S3 request
     * @param {string} options.bucketName S3 Bucket name
     * @param {string} options.action S3 API Action
     * @param {string} options.prefix prefix parameter for ListObjectsV2
     * @param {string} options.startAfter start-after parameter for ListObjectsV2
     * @param {string} options.objectKey Key of the S3 object. For PutObject requests, it is retrieved from options.FileObject.name
     * @param {string} options.folderPath Folder of the S3 object. It should end with / character. For ListObjectsV2, use prefix parameter instead.
     * @param {file.File} options.fileObject File to be upladed to S3
     * @param {string} options.payload Payload required to calculate Hash. For PutObject, it is retrieved from options.FileObject.getContents()
     * @param {AwsUrl} options.awsRegion AWS Region
     * @param {string} options.accessKey Access Key of the AWS user or from the STS request
     * @param {string} options.secretKey SecretKey of the AWS user or from the STS request
     * @param {string} options.sessionToken Token received from STS request
     * @returns {https.ServerResponse} Response of the S3 request
     */
    const s3Requests = (options) => {
        const SERVICE_NAME = 's3';
        let httpMethod = 'GET';
        let requestParams = [];
        let requestOptions = {};
        let requestHeaders = {};
        if (options.sessionToken) {
            requestHeaders['X-Amz-Security-Token'] = options.sessionToken;
        }

        switch (options.action) {
            case 'ListObjectsV2':
                requestParams.push({name: 'list-type', value: 2});
                options.prefix ? requestParams.push({name: 'prefix', value: options.prefix}) : null;
                options.startAfter ? requestParams.push({name: 'start-after', value: options.startAfter}) : null;
                break;
            case 'GetObject': 
                break;
            case 'PutObject' : 
                httpMethod = 'PUT';
                options.objectKey = options.fileObject.name;
                requestOptions.body = options.payload = options.fileObject.getContents();
                requestHeaders['Content-Encoding'] = 'text';
                requestHeaders['Content-Length'] = options.fileObject.size;
                requestHeaders['Content-Type'] = 'plain/text';
                break;
            case 'DeleteObject': 
                httpMethod = 'DELETE';
                break;
        }
        requestOptions.method = httpMethod;

        const awsUrl = generateAwsUrl({
            awsService: SERVICE_NAME,
            awsRegion: options.awsRegion,
            bucketName: options.bucketName,
            folderPath: options.folderPath,
            objectKey: options.objectKey ? options.objectKey : null,
            requestParams: requestParams
        });
        requestOptions.url = `https://${awsUrl.host}${awsUrl.canonicalUri}?${awsUrl.canonicalQueryString}`;

        const xAmzDate = getXAmzDate();
        requestHeaders['host'] = awsUrl.host;
        requestHeaders['x-amz-date'] = xAmzDate
        requestHeaders['Authorization'] = createAuthorizationHeader({
            payload: options.payload,
            awsUrl: awsUrl,
            xAmzDate: xAmzDate,
            awsRegion: options.awsRegion,
            awsService: SERVICE_NAME,
            httpMethod: httpMethod,
            secretKey: options.secretKey,
            accessKey: options.accessKey,
            requestHeaders: requestHeaders
        });
        requestHeaders['Accept'] = 'application/json';

        requestOptions.headers = requestHeaders;

        return https.request(requestOptions);
    }

    /**
     * Sends request to AWS Secrets Manager API. 
     * 
     * @param {object} options Details of the Secrets Manager request
     * @param {string} options.action Secrets Manager API action
     * @param {string} options.secretId Secret name
     * @param {string} options.payload Payload required to calculate Hash. SecretId is set to the payload.
     * @param {AwsUrl} options.awsRegion AWS Region
     * @param {string} options.accessKey Access Key of the AWS user or from the STS request
     * @param {string} options.secretKey SecretKey of the AWS user or from the STS request
     * @param {string} options.sessionToken Token received from STS request
     * @returns {https.ServerResponse} Response of the Secrets Manager request
     */
     const secretsManagerRequests = (options) => {
        const SERVICE_NAME = 'secretsmanager';
        let httpMethod = 'POST';
        let requestParams = [];
        let requestOptions = {};
        let requestHeaders = {
            "X-Amz-Target": `secretsmanager.${options.action}`,
            "Content-Type": "application/x-amz-json-1.1"
        };
        requestOptions.body = options.payload = `{"SecretId": "${options.secretId}"}`;

        if (options.sessionToken) {
            requestHeaders['X-Amz-Security-Token'] = options.sessionToken;
        }

        switch (options.action) {
            case 'GetSecretValue':
                break;
            case 'DescribeSecret': 
                break;
        }
        requestOptions.method = httpMethod;

        const awsUrl = generateAwsUrl({
            awsService: SERVICE_NAME,
            awsRegion: options.awsRegion,
            requestParams: requestParams
        });
        requestOptions.url = `https://${awsUrl.host}${awsUrl.canonicalUri}`;

        const xAmzDate = getXAmzDate();
        requestHeaders['host'] = awsUrl.host;
        requestHeaders['x-amz-date'] = xAmzDate
        requestHeaders['Authorization'] = createAuthorizationHeader({
            payload: options.payload,
            awsUrl: awsUrl,
            xAmzDate: xAmzDate,
            awsRegion: options.awsRegion,
            awsService: SERVICE_NAME,
            httpMethod: httpMethod,
            secretKey: options.secretKey,
            accessKey: options.accessKey,
            requestHeaders: requestHeaders
        });
        requestHeaders['Accept'] = 'application/json';
        requestHeaders['Content-Length'] = requestOptions.body.length;

        requestOptions.headers = requestHeaders;

        return https.request(requestOptions);
    }

    /**
     * Sends request to AWS Security Token Service API. 
     * 
     * @param {object} options Details of the STS request
     * @param {string} options.action STS API action
     * @param {string} options.roleArn ARN of the role
     * @param {string} options.roleSessionName Role Session Name
     * @param {number} options.duration Token validity in seconds
     * @param {string} options.payload Payload required to calculate Hash. SecretId is set to the payload.
     * @param {AwsUrl} options.awsRegion AWS Region
     * @param {string} options.accessKey Access Key of the AWS user
     * @param {string} options.secretKey SecretKey of the AWS user
     * @returns {https.ServerResponse} Response of the STS request
     */
     const stsRequests = (options) => {
        const SERVICE_NAME = 'sts';
        let httpMethod = 'GET';
        let requestParams = [];
        let requestOptions = {};
        let requestHeaders = {
            "Content-Type": "application/x-amz-json-1.1"
        };
        requestParams.push({name: 'Version', value: '2011-06-15'});
        requestParams.push({name: 'Action', value: options.action});

        switch (options.action) {
            case 'AssumeRole':
                requestParams.push({name: 'RoleArn', value: options.roleArn});
                requestParams.push({name: 'RoleSessionName', value: options.roleSessionName});
                requestParams.push({name: 'DurationSeconds', value: options.duration});
                break;
        }
        requestOptions.method = httpMethod;

        const awsUrl = generateAwsUrl({
            awsService: SERVICE_NAME,
            awsRegion: options.awsRegion,
            requestParams: requestParams
        });
        requestOptions.url = `https://${awsUrl.host}${awsUrl.canonicalUri}?${awsUrl.canonicalQueryString}`;

        const xAmzDate = getXAmzDate();
        requestHeaders['host'] = awsUrl.host;
        requestHeaders['x-amz-date'] = xAmzDate
        requestHeaders['Authorization'] = createAuthorizationHeader({
            payload: options.payload,
            awsUrl: awsUrl,
            xAmzDate: xAmzDate,
            awsRegion: options.awsRegion,
            awsService: SERVICE_NAME,
            httpMethod: httpMethod,
            secretKey: options.secretKey,
            accessKey: options.accessKey,
            requestHeaders: requestHeaders
        });
        requestHeaders['Accept'] = 'application/json';

        requestOptions.headers = requestHeaders;

        log.debug('requestOptions', requestOptions);
        return https.request(requestOptions);
    }

    return {
        s3Requests, 
        sqsRequests,
        secretsManagerRequests,
        stsRequests
    }
});