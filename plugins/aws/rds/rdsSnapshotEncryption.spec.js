const expect = require('chai').expect;
var rdsSnapshotEncryption = require('./rdsSnapshotEncryption');

const describeDBSnapshots = [
    {
        "DBSnapshotIdentifier": "testsnapshot",
        "DBInstanceIdentifier": "database-1",
        "Engine": "mysql",
        "AllocatedStorage": 20,
        "Status": "creating",
        "Port": 3306,
        "AvailabilityZone": "us-east-1f",
        "VpcId": "vpc-99de2fe4",
        "InstanceCreateTime": "2021-01-17T22:52:44.376000+00:00",
        "MasterUsername": "admin",
        "EngineVersion": "8.0.20",
        "LicenseModel": "general-public-license",
        "SnapshotType": "manual",
        "OptionGroupName": "default:mysql-8-0",
        "PercentProgress": 0,
        "StorageType": "gp2",
        "Encrypted": true,
        "DBSnapshotArn": "arn:aws:rds:us-east-1:111122223333:snapshot:testsnapshot",
        "IAMDatabaseAuthenticationEnabled": false,
        "ProcessorFeatures": [],
        "KmsKeyId": "a14dea26-1459-4f62-ab85-d5a54293a495",
        "DbiResourceId": "db-RK56DA7XGJNA4OT3BEOFIECBEI",
        "TagList": []
    },
    {
        "DBSnapshotIdentifier": "testsnapshot",
        "DBInstanceIdentifier": "database-1",
        "Engine": "mysql",
        "AllocatedStorage": 20,
        "Status": "creating",
        "Port": 3306,
        "AvailabilityZone": "us-east-1f",
        "VpcId": "vpc-99de2fe4",
        "InstanceCreateTime": "2021-01-17T22:52:44.376000+00:00",
        "MasterUsername": "admin",
        "EngineVersion": "8.0.20",
        "LicenseModel": "general-public-license",
        "SnapshotType": "manual",
        "OptionGroupName": "default:mysql-8-0",
        "PercentProgress": 0,
        "StorageType": "gp2",
        "Encrypted": false,
        "DBSnapshotArn": "arn:aws:rds:us-east-1:111122223333:snapshot:testsnapshot",
        "IAMDatabaseAuthenticationEnabled": false,
        "ProcessorFeatures": [],
        "DbiResourceId": "db-RK56DA7XGJNA4OT3BEOFIECBEI",
        "TagList": []
    }
]

const createCache = (describeDBSnapshots, describeDBSnapshotsErr) => {
    return {
        rds: {
            describeDBSnapshots: {
                'us-east-1': {
                    err: describeDBSnapshotsErr,
                    data: describeDBSnapshots
                }
            },
        }
    };
};

const createNullCache = () => {
    return {
        rds: {
            describeDBSnapshots: {
                'us-east-1': null
            }
        }
    };
};

describe('rdsSnapshotEncryption', function () {
    describe('run', function () {

        it('should PASS if snapshot encryption is enabled via KMS key', function (done) {
            const cache = createCache([describeDBSnapshots[0]], null);
            rdsSnapshotEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if snapshot encryption not enabled', function (done) {
            const cache = createCache([describeDBSnapshots[1]], null);
            rdsSnapshotEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no RDS snapshots found', function (done) {
            const cache = createCache([]);
            rdsSnapshotEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable query for RDS snapshots', function (done) {
            const cache = createCache(null, { message: "Unable to describe db snapshots" });
            rdsSnapshotEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should not return anything if describe db snapshots response not found', function (done) {
            const cache = createNullCache();
            rdsSnapshotEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});