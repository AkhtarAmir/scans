const expect = require('chai').expect;
var missingS3Bucket = require('./missingS3Bucket');

const describeDeliveryChannels = [
    {
        name: 'default',
        s3BucketName: 'test-bucket'
    }
];

const listBuckets = [
    {
        "Name": "test-bucket",
        "CreationDate": "2021-01-13T14:33:37+00:00"
    }
];



const createCache = (describeDeliveryChannels, listBuckets, describeDeliveryChannelsErr, listBucketsErr) => {
    return {
        configservice: {
            describeDeliveryChannels: {
                'us-east-1': {
                    err: describeDeliveryChannelsErr,
                    data: describeDeliveryChannels
                }
            },
        },
        s3: {
            listBuckets: {
                'us-east-1': {
                    err: listBucketsErr,
                    data: listBuckets
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        configservice: {
            describeDeliveryChannels: {
                'us-east-1': null
            }
        }
    };
};

describe('missingS3Bucket', function () {
    describe('run', function () {
        it('should PASS if delivery channel default has active bucket configured', function (done) {
            const cache = createCache([describeDeliveryChannels[0]], listBuckets, null, null);
            missingS3Bucket.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if delivery channel default has missing bucket configured', function (done) {
            const cache = createCache([describeDeliveryChannels[0]], [], null, null);
            missingS3Bucket.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no delivery channels found', function (done) {
            const cache = createCache([], []);
            missingS3Bucket.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to describe delivery channels', function (done) {
            const cache = createCache(null, [], { message: "Unable to describe delivery channels" }, null);
            missingS3Bucket.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to list S3 buckets', function (done) {
            const cache = createCache([describeDeliveryChannels[0]], [], null, { message: "Unable to list buckets" });
            missingS3Bucket.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if descibe delivery channels response not found', function (done) {
            const cache = createNullCache();
            missingS3Bucket.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});