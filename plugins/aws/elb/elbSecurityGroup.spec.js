var expect = require('chai').expect;
const elbSecurityGroup = require('./elbSecurityGroup');

const describeLoadBalancers = [
    {
        "LoadBalancerName": "test-84",
        "DNSName": "test-84-1988801627.us-east-1.elb.amazonaws.com",
        "CanonicalHostedZoneName": "test-84-1988801627.us-east-1.elb.amazonaws.com",
        "CanonicalHostedZoneNameID": "Z35SXDOTRQ7X7K",
        "ListenerDescriptions": [
            {
                "Listener": {
                    "Protocol": "HTTPS",
                    "LoadBalancerPort": 443,
                    "InstanceProtocol": "HTTPS",
                    "InstancePort": 443,
                    "SSLCertificateId": "arn:aws:iam::111122223333:server-certificate/ExampleCertificate"
                },
                "PolicyNames": [
                    "AWSConsole-SSLNegotiationPolicy-test-84-2-1601842068416"
                ]
            }
        ],
        "Policies": {
            "AppCookieStickinessPolicies": [],
            "LBCookieStickinessPolicies": [],
            "OtherPolicies": []
        },
        "BackendServerDescriptions": [],
        "AvailabilityZones": [
            "us-east-1f",
            "us-east-1e",
            "us-east-1d",
            "us-east-1c",
            "us-east-1b",
            "us-east-1a"
        ],
        "Subnets": [
            "subnet-06aa0f60",
            "subnet-673a9a46",
            "subnet-6a8b635b",
            "subnet-aac6b3e7",
            "subnet-c21b84cc",
            "subnet-e83690b7"
        ],
        "VPCId": "vpc-99de2fe4",
        "Instances": [
            {
                "InstanceId": "i-093267d7a579c4bee",
                "InstanceType": "t2.micro",
                "AvailabilityZone": "us-east-1a",
                "LifecycleState": "InService",
                "HealthStatus": "Healthy",
                "LaunchTemplate": {
                    "LaunchTemplateId": "lt-0f1f6b356026abc86",
                    "LaunchTemplateName": "auto-scaling-template",
                    "Version": "1"
                },
                "ProtectedFromScaleIn": false
            }
        ],
        "HealthCheck": {
            "Target": "HTTP:80/index.html",
            "Interval": 30,
            "Timeout": 5,
            "UnhealthyThreshold": 2,
            "HealthyThreshold": 10
        },
        "SourceSecurityGroup": {
            "OwnerAlias": "111122223333",
            "GroupName": "default"
        },
        "SecurityGroups": [
            "sg-aa941691"
        ],
        "CreatedTime": "2020-10-01T17:50:43.330Z",
        "Scheme": "internet-facing"
    },
    {
        "LoadBalancerName": "test-84",
        "DNSName": "test-84-1988801627.us-east-1.elb.amazonaws.com",
        "CanonicalHostedZoneName": "test-84-1988801627.us-east-1.elb.amazonaws.com",
        "CanonicalHostedZoneNameID": "Z35SXDOTRQ7X7K",
        "ListenerDescriptions": [],
        "Policies": {
            "AppCookieStickinessPolicies": [],
            "LBCookieStickinessPolicies": [],
            "OtherPolicies": []
        },
        "BackendServerDescriptions": [],
        "AvailabilityZones": [
            "us-east-1f",
            "us-east-1e",
            "us-east-1d",
            "us-east-1c",
            "us-east-1b",
            "us-east-1a"
        ],
        "Subnets": [
            "subnet-06aa0f60",
            "subnet-673a9a46",
            "subnet-6a8b635b",
            "subnet-aac6b3e7",
            "subnet-c21b84cc",
            "subnet-e83690b7"
        ],
        "VPCId": "vpc-99de2fe4",
        "Instances": [],
        "HealthCheck": {},
        "SourceSecurityGroup": {
            "OwnerAlias": "111122223333",
            "GroupName": "default"
        },
        "SecurityGroups": [
            "sg-aa941691"
        ],
        "CreatedTime": "2020-10-01T17:50:43.330Z",
        "Scheme": "internet-facing"
    }
];

const describeSecurityGroups = [
    {
        "Description": "Master group for Elastic MapReduce created on 2020-08-31T17:07:19.819Z",
        "GroupName": "ElasticMapReduce-master",
        "IpPermissions": [
            {
                "FromPort": 0,
                "IpProtocol": "tcp",
                "IpRanges": [
                    {
                        "CidrIp": "0.0.0.0/0"
                    }
                ],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "ToPort": 443,
                "UserIdGroupPairs": [
                    {
                        "GroupId": "sg-aa941691",
                        "UserId": "111122223333"
                    }
                ]
            },
            {
                "FromPort": 8443,
                "IpProtocol": "tcp",
                "IpRanges": [
                    {
                        "CidrIp": "72.21.196.64/29"
                    }
                ],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "ToPort": 8443,
                "UserIdGroupPairs": []
            }
        ],
        "OwnerId": "111122223333",
        "GroupId": "sg-aa941691",
        "IpPermissionsEgress": [
            {
                "IpProtocol": "-1",
                "IpRanges": [
                    {
                        "CidrIp": "0.0.0.0/0"
                    }
                ],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "UserIdGroupPairs": []
            }
        ],
        "VpcId": "vpc-99de2fe4"
    },
    {
        "Description": "Master group for Elastic MapReduce created on 2020-08-31T17:07:19.819Z",
        "GroupName": "default",
        "IpPermissions": [
            {
                "FromPort": 0,
                "IpProtocol": "tcp",
                "IpRanges": [
                    {
                        "CidrIp": "0.0.0.0/0"
                    }
                ],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "ToPort": 65535,
                "UserIdGroupPairs": [
                    {
                        "GroupId": "sg-001639e564442dfec",
                        "UserId": "111122223333"
                    }
                ]
            },
            {
                "FromPort": 8443,
                "IpProtocol": "tcp",
                "IpRanges": [
                    {
                        "CidrIp": "72.21.196.64/29"
                    }
                ],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "ToPort": 8443,
                "UserIdGroupPairs": []
            }
        ],
        "OwnerId": "111122223333",
        "GroupId": "sg-aa941691",
        "IpPermissionsEgress": [
            {
                "IpProtocol": "-1",
                "IpRanges": [
                    {
                        "CidrIp": "0.0.0.0/0"
                    }
                ],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "UserIdGroupPairs": []
            }
        ],
        "VpcId": "vpc-99de2fe4"
    }
];

const createCache = (describeLoadBalancers, describeSecurityGroups, describeLoadBalancersErr, describeSecurityGroupsErr) => {

    return {
        elb: {
            describeLoadBalancers: {
                'us-east-1': {
                    err: describeLoadBalancersErr,
                    data: describeLoadBalancers
                }
            },
        },
        ec2: {
            describeSecurityGroups: {
                'us-east-1': {
                    err: describeSecurityGroupsErr,
                    data: describeSecurityGroups
                }
            },
        }
    };
};

const createNullCache = () => {
    return {
        elb: {
            describeLoadBalancers: {
                'us-east-1': null
            }
        }
    };
};

describe('elbSecurityGroup', function () {
    describe('run', function () {
        it('should PASS if AWS ELB associated security group(s) allow all listener ports', function (done) {
            const cache = createCache([describeLoadBalancers[0]], describeSecurityGroups);
            elbSecurityGroup.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if AWS ELB associated security group(s) do not allow all listener ports', function (done) {
            const cache = createCache([describeLoadBalancers[0]], [describeSecurityGroups[1]]);
            elbSecurityGroup.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if AWS ELB does not have any listeners configured', function (done) {
            const cache = createCache([describeLoadBalancers[1]], describeSecurityGroups);
            elbSecurityGroup.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no load balancers found', function (done) {
            const cache = createCache([]);
            elbSecurityGroup.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to query for load balancers', function (done) {
            const cache = createCache([describeLoadBalancers[0]], describeSecurityGroups, { message: 'Unable to query for load balancers' });
            elbSecurityGroup.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to describe security groups', function (done) {
            const cache = createCache([describeLoadBalancers[0]], null, null, { message: 'Unable to describe security groups' });
            elbSecurityGroup.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should not return anything if describe load balancers response is not found', function (done) {
            const cache = createNullCache();
            elbSecurityGroup.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
}); 