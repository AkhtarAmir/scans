var expect = require('chai').expect;
var catalogEncryptionAtRest = require('./catalogEncryptionAtRest');

const getDataCatalogEncryptionSettings = [
    {
        "EncryptionAtRest": {
            "CatalogEncryptionMode": "SSE-KMS",
            "SseAwsKmsKeyId": "arn:aws:kms:us-east-1:111122223333:key/75e9285f-ae6b-4c36-9405-06e67bcc7ef1"
        },
        "ConnectionPasswordEncryption": {
            "ReturnConnectionPasswordEncrypted": true,
            "AwsKmsKeyId": "arn:aws:kms:us-east-1:111122223333:key/e400fb3c-7bb5-4e7e-8ecc-25098282573a"
        }
    },
    {
        "EncryptionAtRest": {
            "CatalogEncryptionMode": "DISABLED"
        },
        "ConnectionPasswordEncryption": {
            "ReturnConnectionPasswordEncrypted": true,
            "AwsKmsKeyId": "arn:aws:kms:us-east-1:111122223333:key/e400fb3c-7bb5-4e7e-8ecc-25098282573a"
        }
    }
];

const createCache = (encryptionSettings) => {
    return {
        glue: {
            getDataCatalogEncryptionSettings: {
                'us-east-1': {
                    data: encryptionSettings
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        glue: {
            getDataCatalogEncryptionSettings: {
                'us-east-1': {
                    err: {
                        message: 'error getting AWS Glue data catalog encryption settings'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        glue: {
            getDataCatalogEncryptionSettings: {
                'us-east-1': null
            }
        },
    };
};

describe('catalogEncryptionAtRest', function () {
    describe('run', function () {
        it('should PASS if AWS Glue data catalog encryption settings has encryption at rest enabled', function (done) {
            const cache = createCache(getDataCatalogEncryptionSettings[0]);
            catalogEncryptionAtRest.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if AWS Glue data catalog encryption settings has encryption at rest disabled', function (done) {
            const cache = createCache(getDataCatalogEncryptionSettings[1]);
            catalogEncryptionAtRest.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if No AWS Glue data catalog encryption settings found', function (done) {
            const cache = createCache();
            catalogEncryptionAtRest.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to get AWS Glue data catalog encryption settings', function (done) {
            const cache = createErrorCache();
            catalogEncryptionAtRest.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if get data catalog encryption settings response is not found', function (done) {
            const cache = createNullCache();
            catalogEncryptionAtRest.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
}); 