const expect = require('chai').expect;
var rdsAutomatedBackups = require('./rdsAutomatedBackups');

const describeDBInstances = [
    {
        "DBInstanceIdentifier": "database-1",
        "DBInstanceClass": "db.t2.micro",
        "Engine": "mysql",
        "DBInstanceStatus": "creating",
        "MasterUsername": "admin",
        "DBName": "testdb",
        "AllocatedStorage": 20,
        "PreferredBackupWindow": "07:23-07:53",
        "BackupRetentionPeriod": 7,
        "DBSecurityGroups": [],
        "VpcSecurityGroups": [
            {
                "VpcSecurityGroupId": "sg-aa941691",
                "Status": "active"
            }
        ],
        "DBParameterGroups": [
            {
                "DBParameterGroupName": "default.mysql8.0",
                "ParameterApplyStatus": "in-sync"
            }
        ],
        "DBSubnetGroup": {
            "DBSubnetGroupName": "default-vpc-99de2fe4",
            "DBSubnetGroupDescription": "Created from the RDS Management Console",
            "VpcId": "vpc-99de2fe4",
            "SubnetGroupStatus": "Complete",
            "Subnets": []
        },
        "PreferredMaintenanceWindow": "mon:03:35-mon:04:05",
        "PendingModifiedValues": {
            "MasterUserPassword": "****",
            "PendingCloudwatchLogsExports": {
                "LogTypesToEnable": [
                    "error"
                ]
            }
        },
        "MultiAZ": false,
        "EngineVersion": "8.0.20",
        "AutoMinorVersionUpgrade": true,
        "ReadReplicaDBInstanceIdentifiers": [],
        "LicenseModel": "general-public-license",
        "OptionGroupMemberships": [
            {
                "OptionGroupName": "default:mysql-8-0",
                "Status": "in-sync"
            }
        ],
        "PubliclyAccessible": false,
        "StorageType": "gp2",
        "DbInstancePort": 0,
        "StorageEncrypted": false,
        "DbiResourceId": "db-RK56DA7XGJNA4OT3BEOFIECBEI",
        "CACertificateIdentifier": "rds-ca-2019",
        "DomainMemberships": [],
        "CopyTagsToSnapshot": true,
        "MonitoringInterval": 0,
        "DBInstanceArn": "arn:aws:rds:us-east-1:111122223333:db:database-1",
        "IAMDatabaseAuthenticationEnabled": false,
        "PerformanceInsightsEnabled": false,
        "DeletionProtection": false,
        "AssociatedRoles": [],
        "TagList": []
    },
    {
        "DBInstanceIdentifier": "database-1",
        "DBInstanceClass": "db.t2.micro",
        "Engine": "mysql",
        "DBInstanceStatus": "creating",
        "MasterUsername": "admin",
        "DBName": "testdb",
        "AllocatedStorage": 20,
        "PreferredBackupWindow": "07:23-07:53",
        "BackupRetentionPeriod": 3,
        "DBSecurityGroups": [],
        "VpcSecurityGroups": [
            {
                "VpcSecurityGroupId": "sg-aa941691",
                "Status": "active"
            }
        ],
        "DBParameterGroups": [
            {
                "DBParameterGroupName": "default.mysql8.0",
                "ParameterApplyStatus": "in-sync"
            }
        ],
        "DBSubnetGroup": {
            "DBSubnetGroupName": "default-vpc-99de2fe4",
            "DBSubnetGroupDescription": "Created from the RDS Management Console",
            "VpcId": "vpc-99de2fe4",
            "SubnetGroupStatus": "Complete",
            "Subnets": []
        },
        "PreferredMaintenanceWindow": "mon:03:35-mon:04:05",
        "PendingModifiedValues": {
            "MasterUserPassword": "****",
            "PendingCloudwatchLogsExports": {
                "LogTypesToEnable": [
                    "error"
                ]
            }
        },
        "MultiAZ": false,
        "EngineVersion": "8.0.20",
        "AutoMinorVersionUpgrade": true,
        "ReadReplicaDBInstanceIdentifiers": [],
        "LicenseModel": "general-public-license",
        "OptionGroupMemberships": [
            {
                "OptionGroupName": "default:mysql-8-0",
                "Status": "in-sync"
            }
        ],
        "PubliclyAccessible": false,
        "StorageType": "gp2",
        "DbInstancePort": 0,
        "StorageEncrypted": false,
        "DbiResourceId": "db-RK56DA7XGJNA4OT3BEOFIECBEI",
        "CACertificateIdentifier": "rds-ca-2019",
        "DomainMemberships": [],
        "CopyTagsToSnapshot": true,
        "MonitoringInterval": 0,
        "DBInstanceArn": "arn:aws:rds:us-east-1:111122223333:db:database-1",
        "IAMDatabaseAuthenticationEnabled": false,
        "PerformanceInsightsEnabled": false,
        "DeletionProtection": false,
        "AssociatedRoles": [],
        "TagList": []
    },
    {
        "DBInstanceIdentifier": "database-1",
        "DBInstanceClass": "db.t2.micro",
        "Engine": "mysql",
        "DBInstanceStatus": "creating",
        "MasterUsername": "admin",
        "DBName": "testdb",
        "AllocatedStorage": 20,
        "PreferredBackupWindow": "07:23-07:53",
        "DBSecurityGroups": [],
        "VpcSecurityGroups": [
            {
                "VpcSecurityGroupId": "sg-aa941691",
                "Status": "active"
            }
        ],
        "DBParameterGroups": [
            {
                "DBParameterGroupName": "default.mysql8.0",
                "ParameterApplyStatus": "in-sync"
            }
        ],
        "DBSubnetGroup": {
            "DBSubnetGroupName": "default-vpc-99de2fe4",
            "DBSubnetGroupDescription": "Created from the RDS Management Console",
            "VpcId": "vpc-99de2fe4",
            "SubnetGroupStatus": "Complete",
            "Subnets": []
        },
        "PreferredMaintenanceWindow": "mon:03:35-mon:04:05",
        "PendingModifiedValues": {
            "MasterUserPassword": "****",
            "PendingCloudwatchLogsExports": {
                "LogTypesToEnable": [
                    "error"
                ]
            }
        },
        "MultiAZ": false,
        "EngineVersion": "8.0.20",
        "AutoMinorVersionUpgrade": true,
        "ReadReplicaDBInstanceIdentifiers": [],
        "LicenseModel": "general-public-license",
        "OptionGroupMemberships": [
            {
                "OptionGroupName": "default:mysql-8-0",
                "Status": "in-sync"
            }
        ],
        "PubliclyAccessible": false,
        "StorageType": "gp2",
        "DbInstancePort": 0,
        "StorageEncrypted": false,
        "DbiResourceId": "db-RK56DA7XGJNA4OT3BEOFIECBEI",
        "CACertificateIdentifier": "rds-ca-2019",
        "DomainMemberships": [],
        "CopyTagsToSnapshot": true,
        "MonitoringInterval": 0,
        "DBInstanceArn": "arn:aws:rds:us-east-1:111122223333:db:database-1",
        "IAMDatabaseAuthenticationEnabled": false,
        "PerformanceInsightsEnabled": false,
        "DeletionProtection": false,
        "AssociatedRoles": [],
        "TagList": []
    }
]

const createCache = (describeDBInstances, describeDBInstancesErr) => {
    return {
        rds: {
            describeDBInstances: {
                'us-east-1': {
                    err: describeDBInstancesErr,
                    data: describeDBInstances
                }
            },
        }
    };
};

const createNullCache = () => {
    return {
        rds: {
            describeDBInstances: {
                'us-east-1': null
            }
        }
    };
};

describe('rdsAutomatedBackups', function () {
    describe('run', function () {

        it('should PASS if automated backups are enabled with sufficient retention period', function (done) {
            const cache = createCache([describeDBInstances[0]], null);
            rdsAutomatedBackups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should WARN if automated backups are enabled but do not have sufficient retention period', function (done) {
            const cache = createCache([describeDBInstances[1]], null);
            rdsAutomatedBackups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if automated backups are not enabled', function (done) {
            const cache = createCache([describeDBInstances[2]], null);
            rdsAutomatedBackups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no RDS instances found', function (done) {
            const cache = createCache([]);
            rdsAutomatedBackups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable query for RDS instances', function (done) {
            const cache = createCache(null, { message: "Unable to describe db instances" });
            rdsAutomatedBackups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should not return anything if describe db instances response not found', function (done) {
            const cache = createNullCache();
            rdsAutomatedBackups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});