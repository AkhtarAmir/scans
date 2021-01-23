const expect = require('chai').expect;
var rdsLoggingEnabled = require('./rdsLoggingEnabled');

const describeDBInstances = [
    {
        "DBInstanceIdentifier": "database-1",
        "DBInstanceClass": "db.t2.micro",
        "Engine": "mysql",
        "DBInstanceStatus": "creating",
        "EnabledCloudwatchLogsExports": [
            "error"
        ],
        "MasterUsername": "admin",
        "AllocatedStorage": 20,
        "PreferredBackupWindow": "04:25-04:55",
        "BackupRetentionPeriod": 0,
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
        "PreferredMaintenanceWindow": "sat:07:00-sat:07:30",
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
        "DbiResourceId": "db-6VW7CTYMH774GZPXY7YPU5AXLM",
        "CACertificateIdentifier": "rds-ca-2019",
        "DomainMemberships": [],
        "CopyTagsToSnapshot": true,
        "MonitoringInterval": 0,
        "DBInstanceArn": "arn:aws:rds:us-east-1:111122223333:db:database-1",
        "IAMDatabaseAuthenticationEnabled": false,
        "PerformanceInsightsEnabled": false,
        "DeletionProtection": false,
        "AssociatedRoles": [],
        "MaxAllocatedStorage": 1000,
        "TagList": []
    },
    {
        "DBInstanceIdentifier": "database-1",
        "DBInstanceClass": "db.t2.micro",
        "Engine": "aurora",
        "DBInstanceStatus": "creating",
        "MasterUsername": "admin",
        "AllocatedStorage": 20,
        "PreferredBackupWindow": "04:25-04:55",
        "BackupRetentionPeriod": 0,
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
        "PreferredMaintenanceWindow": "sat:07:00-sat:07:30",
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
        "DbiResourceId": "db-6VW7CTYMH774GZPXY7YPU5AXLM",
        "CACertificateIdentifier": "rds-ca-2019",
        "DomainMemberships": [],
        "CopyTagsToSnapshot": true,
        "MonitoringInterval": 0,
        "DBInstanceArn": "arn:aws:rds:us-east-1:111122223333:db:database-1",
        "IAMDatabaseAuthenticationEnabled": false,
        "PerformanceInsightsEnabled": false,
        "DeletionProtection": false,
        "AssociatedRoles": [],
        "MaxAllocatedStorage": 1000,
        "TagList": []
    },
    {
        "DBInstanceIdentifier": "database-1",
        "DBInstanceClass": "db.t2.micro",
        "Engine": "mysql",
        "DBInstanceStatus": "creating",
        "MasterUsername": "admin",
        "AllocatedStorage": 20,
        "PreferredBackupWindow": "04:25-04:55",
        "BackupRetentionPeriod": 0,
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
        "PreferredMaintenanceWindow": "sat:07:00-sat:07:30",
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
        "DbiResourceId": "db-6VW7CTYMH774GZPXY7YPU5AXLM",
        "CACertificateIdentifier": "rds-ca-2019",
        "DomainMemberships": [],
        "CopyTagsToSnapshot": true,
        "MonitoringInterval": 0,
        "DBInstanceArn": "arn:aws:rds:us-east-1:111122223333:db:database-1",
        "IAMDatabaseAuthenticationEnabled": false,
        "PerformanceInsightsEnabled": false,
        "DeletionProtection": false,
        "AssociatedRoles": [],
        "MaxAllocatedStorage": 1000,
        "TagList": []
    }
]

const describeDBEngineVersions = [
    {
        "Engine": "mysql",
        "EngineVersion": "8.0.20",
        "DBParameterGroupFamily": "mysql8.0",
        "DBEngineDescription": "MySQL Community Edition",
        "DBEngineVersionDescription": "mysql 8.0.20",
        "ValidUpgradeTarget": [
            {
                "Engine": "mysql",
                "EngineVersion": "8.0.20",
                "Description": "MySQL 8.0.20",
                "AutoUpgrade": false,
                "IsMajorVersionUpgrade": false
            },
        ],
        "ExportableLogTypes": [
            "audit",
            "error",
            "general",
            "slowquery"
        ],
        "SupportsLogExportsToCloudwatchLogs": true,
        "SupportsReadReplica": true,
        "SupportedFeatureNames": [],
        "Status": "available",
        "SupportsParallelQuery": false,
        "SupportsGlobalDatabases": false
    }
]

const createCache = (describeDBInstances, describeDBEngineVersions, describeDBInstancesErr, describeDBEngineVersionsErr) => {
    return {
        rds: {
            describeDBInstances: {
                'us-east-1': {
                    err: describeDBInstancesErr,
                    data: describeDBInstances
                }
            },
            describeDBEngineVersions: {
                'us-east-1': {
                    err: describeDBEngineVersionsErr,
                    data: describeDBEngineVersions
                }
            }
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

describe('rdsLoggingEnabled', function () {
    describe('run', function () {
        it('should PASS if logging is enabled', function (done) {
            const cache = createCache([describeDBInstances[0]], describeDBEngineVersions, null, null);
            rdsLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if logging is not enabled, but cannot be enabled', function (done) {
            const cache = createCache([describeDBInstances[1]], describeDBEngineVersions, null, null);
            rdsLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if logging is not enabled', function (done) {
            const cache = createCache([describeDBInstances[2]], describeDBEngineVersions, null, null);
            rdsLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no RDS instances found', function (done) {
            const cache = createCache([]);
            rdsLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to query for RDS instances', function (done) {
            const cache = createCache(null, null, { message: "Unable to query for RDS instances" }, null);
            rdsLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to query for RDS engine versions', function (done) {
            const cache = createCache([describeDBInstances[0]], describeDBEngineVersions[1], null, { message: "Unable to query for RDS engine versions" });
            rdsLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should not return anything if list rds functions response not found', function (done) {
            const cache = createNullCache();
            rdsLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});