const expect = require('chai').expect;
var includeGlobalResources = require('./includeGlobalResources');

const describeConfigurationRecorders = [
    {
        "name": "default",
        "roleARN": "arn:aws:iam::111122223333:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig",
        "recordingGroup": {
            "allSupported": true,
            "includeGlobalResourceTypes": true,
            "resourceTypes": []
        }
    },
    {
        "name": "default",
        "roleARN": "arn:aws:iam::111122223333:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig",
        "recordingGroup": {
            "allSupported": true,
            "includeGlobalResourceTypes": false,
            "resourceTypes": []
        }
    }
];

const createCache = (describeConfigurationRecorders, describeConfigurationRecordersErr) => {
    return {
        configservice: {
            describeConfigurationRecorders: {
                'us-east-1': {
                    err: describeConfigurationRecordersErr,
                    data: describeConfigurationRecorders
                }
            },
        },
    };
};

const createNullCache = () => {
    return {
        configservice: {
            describeConfigurationRecorders: {
                'us-east-1': null
            }
        }
    };
};

describe('includeGlobalResources', function () {
    describe('run', function () {
        it('should PASS if AWS Config is configured to include Global resources', function (done) {
            const cache = createCache([describeConfigurationRecorders[0]], null);
            includeGlobalResources.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if AWS Config is not configured to include Global resources', function (done) {
            const cache = createCache([describeConfigurationRecorders[1]], null);
            includeGlobalResources.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no configuration recorders found', function (done) {
            const cache = createCache([]);
            includeGlobalResources.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to describe configuration recorders', function (done) {
            const cache = createCache(null, { message: "Unable to describe configuration recorders" });
            includeGlobalResources.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if descibe configuration recorders response not found', function (done) {
            const cache = createNullCache();
            includeGlobalResources.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});