var expect = require('chai').expect;
const elbv2NoInstances = require('./elbv2NoInstances');

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

const describeTargetGroups = [
    {
        "TargetGroups": [
            {
                "TargetGroupArn": "arn:aws:elasticloadbalancing:us-east-1:560213429563:targetgroup/tmp-tg/d2e04b9c8a45baa3",
                "TargetGroupName": "tmp-tg",
                "Protocol": "TCP",
                "Port": 80,
                "VpcId": "vpc-99de2fe4",
                "HealthCheckProtocol": "TCP",
                "HealthCheckPort": "traffic-port",
                "HealthCheckEnabled": true,
                "HealthCheckIntervalSeconds": 30,
                "HealthCheckTimeoutSeconds": 10,
                "HealthyThresholdCount": 3,
                "UnhealthyThresholdCount": 3,
                "LoadBalancerArns": [
                    "arn:aws:elasticloadbalancing:us-east-1:560213429563:loadbalancer/net/test-spec-network/761bb44c97dd0d02"
                ],
                "TargetType": "instance"
            }
        ]
    }
];


const createCache = (elbv2, targets) => {
    if(elbv2 && elbv2.length && elbv2[0].DNSName) var elbDnsName = elbv2[0].DNSName;
    return {
        elbv2:{
            describeLoadBalancers: {
                'us-east-1': {
                    data: elbv2
                },
            },
            describeTargetGroups: {
                'us-east-1': {
                    [elbDnsName]: {
                        data: targets
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
            describeTargetGroups: {
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
            describeTargetGroups: {
                'us-east-1': null,
            },
        },
    };
};

describe('elbv2NoInstances', function () {
    describe('run', function () {
        it('should PASS if ELB has target groups', function (done) {
            const cache = createCache([describeLoadBalancers[0]], describeTargetGroups[0]);
            elbv2NoInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if ELB does not have target groups', function (done) {
            const cache = createCache([describeLoadBalancers[0]], []);
            elbv2NoInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if No load balancers found', function (done) {
            const cache = createCache([]);
            elbv2NoInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if No load balancer targets found', function (done) {
            const cache = createCache([describeLoadBalancers[0]], []);
            elbv2NoInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if unable to describe load balancers', function (done) {
            const cache = createErrorCache();
            elbv2NoInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to describe load balancer targets', function (done) {
            const cache = createCache([describeLoadBalancers[0]]);
            elbv2NoInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe load balancers response is not found', function (done) {
            const cache = createNullCache();
            elbv2NoInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
