var expect = require('chai').expect;
const elbv2LoggingEnabled = require('./elbv2LoggingEnabled');

const describeLoadBalancers = [
    {
        "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/test-spec/61d3676f45708904",
        "DNSName": "test-spec-1746326582.us-east-1.elb.amazonaws.com",
        "CanonicalHostedZoneId": "Z35SXDOTRQ7X7K",
        "CreatedTime": "2020-11-07T00:20:34.480Z",
        "LoadBalancerName": "test-spec",
        "Scheme": "internet-facing",
        "VpcId": "vpc-99de2fe4",
        "State": {
            "Code": "active"
        },
        "Type": "application",
        "AvailabilityZones": [
            {
                "ZoneName": "us-east-1a",
                "SubnetId": "subnet-06aa0f60",
                "LoadBalancerAddresses": []
            },
            {
                "ZoneName": "us-east-1b",
                "SubnetId": "subnet-673a9a46",
                "LoadBalancerAddresses": []
            }
        ],
        "SecurityGroups": [
            "sg-aa941691"
        ],
        "IpAddressType": "ipv4"
    }
];

const describeLoadBalancerAttributes = [
    {
        "Attributes": [
            {
                "Key": "access_logs.s3.enabled",
                "Value": "true"
            },
            {
                "Key": "load_balancing.cross_zone.enabled",
                "Value": "false"
            },
            {
                "Key": "access_logs.s3.prefix",
                "Value": ""
            },
            {
                "Key": "deletion_protection.enabled",
                "Value": "false"
            },
            {
                "Key": "access_logs.s3.bucket",
                "Value": ""
            }
        ]
    },
    {
        "Attributes": [
            {
                "Key": "access_logs.s3.enabled",
                "Value": "false"
            },
            {
                "Key": "load_balancing.cross_zone.enabled",
                "Value": "false"
            },
            {
                "Key": "access_logs.s3.prefix",
                "Value": ""
            },
            {
                "Key": "deletion_protection.enabled",
                "Value": "false"
            },
            {
                "Key": "access_logs.s3.bucket",
                "Value": ""
            }
        ]
    }
];


const createCache = (elbv2, attributes) => {
    if(elbv2 && elbv2.length && elbv2[0].DNSName) var elbDnsName = elbv2[0].DNSName;
    return {
        elbv2:{
            describeLoadBalancers: {
                'us-east-1': {
                    data: elbv2
                },
            },
            describeLoadBalancerAttributes: {
                'us-east-1': {
                    [elbDnsName]: {
                        data: attributes
                    },
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        elbv2: {
            describeLoadBalancers: {
                'us-east-1': {
                    err: {
                        message: 'error describing load balancers'
                    },
                },
            },
            describeLoadBalancerAttributes: {
                'us-east-1': {
                    err: {
                        message: 'error describing load balancer attributes'
                    },
                },
            },
        }
    };
};

const createNullCache = () => {
    return {
        elbv2: {
            describeLoadBalancers: {
                'us-east-1': null,
            },
            describeLoadBalancerAttributes: {
                'us-east-1': null,
            },
        },
    };
};

describe('elbv2LoggingEnabled', function () {
    describe('run', function () {
        it('should PASS if logging is enabled for load balancer', function (done) {
            const cache = createCache([describeLoadBalancers[0]], describeLoadBalancerAttributes[0]);
            elbv2LoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if logging is not enabled for load balancer', function (done) {
            const cache = createCache([describeLoadBalancers[0]], describeLoadBalancerAttributes[1]);
            elbv2LoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if No load balancers found', function (done) {
            const cache = createCache([]);
            elbv2LoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if No load balancer Attributes found', function (done) {
            const cache = createCache([describeLoadBalancers[0]], []);
            elbv2LoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if unable to describe load balancers', function (done) {
            const cache = createErrorCache();
            elbv2LoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to describe load balancer attributes', function (done) {
            const cache = createCache([describeLoadBalancers[0]]);
            elbv2LoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe load balancers response is not found', function (done) {
            const cache = createNullCache();
            elbv2LoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
