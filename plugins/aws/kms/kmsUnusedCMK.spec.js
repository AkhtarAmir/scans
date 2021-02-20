var expect = require('chai').expect;
const kmsUnusedCMK = require('./kmsUnusedCMK');

const listKeys = [
    {
        "KeyId": "0723d7e2-8655-4553-b4e3-20084f6bddba",
        "KeyArn": "arn:aws:kms:us-east-1:111122223333:key/0723d7e2-8655-4553-b4e3-20084f6bddba"
    }
];

const describeKey = [
    {
        "KeyMetadata": {
            "AWSAccountId": "111122223333",
            "KeyId": "a5e8b8f5-7208-4920-ac84-bd5466c08656",
            "Arn": "arn:aws:kms:us-east-1:111122223333:key/a5e8b8f5-7208-4920-ac84-bd5466c08656",
            "CreationDate": "2021-02-14T23:17:05.164000+05:00",
            "Enabled": true,
            "Description": "",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeyState": "PendingDeletion",
            "DeletionDate": "2021-02-21T23:24:42.917000+05:00",
            "Origin": "AWS_KMS",
            "KeyManager": "CUSTOMER",
            "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
            "EncryptionAlgorithms": [
                "SYMMETRIC_DEFAULT"
            ]
        }
    },
    {
        "KeyMetadata": {
            "AWSAccountId": "111122223333",
            "KeyId": "a5e8b8f5-7208-4920-ac84-bd5466c08656",
            "Arn": "arn:aws:kms:us-east-1:111122223333:key/a5e8b8f5-7208-4920-ac84-bd5466c08656",
            "CreationDate": "2021-02-14T23:17:05.164000+05:00",
            "Enabled": false,
            "Description": "",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeyState": "PendingDeletion",
            "DeletionDate": "2021-02-21T23:24:42.917000+05:00",
            "Origin": "AWS_KMS",
            "KeyManager": "CUSTOMER",
            "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
            "EncryptionAlgorithms": [
                "SYMMETRIC_DEFAULT"
            ]
        }
    },
    {
        "KeyMetadata": {
            "AWSAccountId": "111122223333",
            "KeyId": "a5e8b8f5-7208-4920-ac84-bd5466c08656",
            "Arn": "arn:aws:kms:us-east-1:111122223333:key/a5e8b8f5-7208-4920-ac84-bd5466c08656",
            "CreationDate": "2021-02-14T23:17:05.164000+05:00",
            "Enabled": false,
            "Description": "Default master key that protects my RDS instances",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeyState": "PendingDeletion",
            "DeletionDate": "2021-02-21T23:24:42.917000+05:00",
            "Origin": "AWS_KMS",
            "KeyManager": "CUSTOMER",
            "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
            "EncryptionAlgorithms": [
                "SYMMETRIC_DEFAULT"
            ]
        }
    }
];

const createCache = (listKeys, describeKey, listKeysErr, describeKeyErr) => {
    var keyId = (listKeys && listKeys.length) ? listKeys[0].KeyId : null;

    return {
        kms: {
            listKeys: {
                'us-east-1': {
                    err: listKeysErr,
                    data: listKeys
                }
            },
            describeKey: {
                'us-east-1': {
                    [keyId]: {
                        err: describeKeyErr,
                        data: describeKey
                    }
                }
            },
        }
    };
};

const createNullCache = () => {
    return {
        kms: {
            listKeys: {
                'us-east-1': null
            }
        }
    };
};

describe('kmsUnusedCMK', function () {
    describe('run', function () {
        it('should PASS if KMS Customer Master Key is enabled', function (done) {
            const cache = createCache([listKeys[0]], describeKey[0]);
            kmsUnusedCMK.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if KMS Customer Master Key is disabled', function (done) {
            const cache = createCache([listKeys[0]], describeKey[1]);
            kmsUnusedCMK.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no KMS keys found', function (done) {
            const cache = createCache([]);
            kmsUnusedCMK.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
        
        it('should PASS if no KMS Customer Master Keys found', function (done) {
            const cache = createCache([listKeys[0]], describeKey[2]);
            kmsUnusedCMK.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache([listKeys[0]], describeKey[1], { message: 'Unable to list KMS keys' });
            kmsUnusedCMK.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to describe key', function (done) {
            const cache = createCache([listKeys[0]], null, null, { message: 'Unable to describe key' });
            kmsUnusedCMK.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should not return anything if list keys response is not found', function (done) {
            const cache = createNullCache();
            kmsUnusedCMK.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
}); 