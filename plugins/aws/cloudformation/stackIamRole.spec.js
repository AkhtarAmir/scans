var expect = require('chai').expect;
const stackIamRole = require('./stackIamRole');

const listStacks = [
    {
        "StackId": "arn:aws:cloudformation:us-east-1:111122223333:stack/AKD/081ed430-3733-11eb-a560-12e26def3eab",
        "StackName": "AKD",
        "CreationTime": "2020-12-05T19:49:48.498000+00:00",
        "StackStatus": "CREATE_COMPLETE",
        "DriftInformation": {
            "StackDriftStatus": "IN_SYNC",
            "LastCheckTimestamp": "2020-12-05T20:37:03.931000+00:00"
        }
    },
];

const describeStacks = [
    {
        "Stacks": [ 
            {
                "StackId": "arn:aws:cloudformation:us-east-1:000011112222:stack/AKD/081ed430-3733-11eb-a560-12e26def3eab",
                "StackName": "AKD",
                "CreationTime": "2020-12-05T19:49:48.498000+00:00",
                "RollbackConfiguration": {
                    "RollbackTriggers": []
                },
                "StackStatus": "CREATE_COMPLETE",
                "DisableRollback": false,
                "NotificationARNs": ["arn:aws:sns:us-east-1:1234567890123456:mytopic"],
                "RoleARN": "arn:aws:iam::111122223333:role/CloudFormationRole",
                "Tags": [],
                "EnableTerminationProtection": true,
                "DriftInformation": {
                    "StackDriftStatus": "IN_SYNC",
                    "LastCheckTimestamp": "2020-12-05T20:37:03.931000+00:00"
                },
            }
        ]
    },
    {
        "Stacks": [ 
            {
                "StackId": "arn:aws:cloudformation:us-east-1:111122223333:stack/AKD/081ed430-3733-11eb-a560-12e26def3eab",
                "StackName": "AKD",
                "CreationTime": "2020-12-05T19:49:48.498000+00:00",
                "RollbackConfiguration": {
                    "RollbackTriggers": []
                },
                "StackStatus": "CREATE_COMPLETE",
                "DisableRollback": false,
                "NotificationARNs": [],
                "Tags": [],
                "EnableTerminationProtection": true,
                "DriftInformation": {
                    "StackDriftStatus": "IN_SYNC",
                    "LastCheckTimestamp": "2020-12-05T20:37:03.931000+00:00"
                }
            }
        ]
    }
]

const createCache = (listStacks, describeStacks, listStacksErr, describeStacksErr) => {
    var stackName = (listStacks && listStacks.length) ? listStacks[0].StackName : null;
    return {
        cloudformation: {
            listStacks: {
                'us-east-1': {
                    err: listStacksErr,
                    data: listStacks
                }
            },
            describeStacks: {
                'us-east-1': {
                    [stackName]: {
                        err: describeStacksErr,
                        data: describeStacks
                    }
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        cloudformation: {
            listStacks: {
                'us-east-1': null
            }
        }
    };
};

describe('stackIamRole', function () {
    describe('run', function () {
        it('should PASS if CloudFormation stack has IAM role associated', function (done) {
            const cache = createCache([listStacks[0]], describeStacks[0], null, null);
            stackIamRole.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if CloudFormation stack does not have IAM role associated', function (done) {
            const cache = createCache([listStacks[0]], describeStacks[1], null, null);
            stackIamRole.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no CloudFormation stacks found', function (done) {
            const cache = createCache([]);
            stackIamRole.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to query for CloudFormation stacks', function (done) {
            const cache = createCache(null, null, { message: "Unable to list stacks" }, null);
            stackIamRole.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to query for CloudFormation stack details', function (done) {
            const cache = createCache([listStacks[0]], describeStacks[1], null, { message: "Unable to describe stacks" });
            stackIamRole.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should not return anything if list stacks response not found', function (done) {
            const cache = createNullCache();
            stackIamRole.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
}); 