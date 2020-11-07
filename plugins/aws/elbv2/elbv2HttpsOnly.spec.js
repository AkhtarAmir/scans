var expect = require('chai').expect;
const elbv2HttpsOnly = require('./elbv2HttpsOnly');

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
    },
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
        "Type": "network",
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

const describeListeners = [
    {
        "Listeners": [{
            "ListenerArn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:listener/app/test-spec/61d3676f45708904/609f74dd72f37780",
            "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/test-spec/61d3676f45708904",
            "Port": 443,
            "Protocol": "HTTPS",
            "Certificates": [
                {
                    "CertificateArn": "arn:aws:iam::111122223333:server-certificate/ExampleCertificate"
                }
            ],
            "SslPolicy": "ELBSecurityPolicy-2016-08",
            "DefaultActions": [
                {
                    "Type": "redirect",
                    "Order": 1,
                    "RedirectConfig": {
                        "Protocol": "HTTPS",
                        "Port": "445",
                        "Host": "#{host}",
                        "Path": "/#{path}",
                        "Query": "#{query}",
                        "StatusCode": "HTTP_301"
                    }
                }
            ]
        }],
    },
    {
        "Listeners": [{
            "ListenerArn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:listener/app/test-spec/61d3676f45708904/5e8d46c9de94cc99",
            "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/test-spec/61d3676f45708904",
            "Port": 80,
            "Protocol": "HTTP",
            "DefaultActions": [
                {
                    "Type": "forward",
                    "TargetGroupArn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/temp-tg/fee5b45af37af625",
                    "ForwardConfig": {
                        "TargetGroups": [
                            {
                                "TargetGroupArn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/temp-tg/fee5b45af37af625",
                                "Weight": 1
                            }
                        ],
                        "TargetGroupStickinessConfig": {
                            "Enabled": false
                        }
                    }
                }
            ]
        }]
    }
];


const createCache = (elbv2, listeners) => {
    if(elbv2 && elbv2.length && elbv2[0].DNSName) var elbDnsName = elbv2[0].DNSName;
    return {
        elbv2:{
            describeLoadBalancers: {
                'us-east-1': {
                    data: elbv2
                },
            },
            describeListeners: {
                'us-east-1': {
                    [elbDnsName]: {
                        data: listeners
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
            describeListeners: {
                'us-east-1': {
                    err: {
                        message: 'error describing load balancer listeners'
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
            describeListeners: {
                'us-east-1': null,
            },
        },
    };
};

describe('elbv2HttpsOnly', function () {
    describe('run', function () {
        it('should PASS if load balancer has HTTPS-only listeners', function (done) {
            const cache = createCache([describeLoadBalancers[0]], describeListeners[0]);
            elbv2HttpsOnly.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
        
        it('should FAIL if load balancer has non HTTPS listeners', function (done) {
            const cache = createCache([describeLoadBalancers[0]], describeListeners[1]);
            elbv2HttpsOnly.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });
        
        it('should PASS if No Application Load Balancers found', function (done) {
            const cache = createCache([describeLoadBalancers[1]]);
            elbv2HttpsOnly.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
        
        it('should PASS if No Load Balancers found', function (done) {
            const cache = createCache([]);
            elbv2HttpsOnly.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
        
        it('should PASS if No Load Balancer Listeners found', function (done) {
            const cache = createCache([describeLoadBalancers[0]], []);
            elbv2HttpsOnly.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
        
        it('should UNKNOWN if unable to describe load balancers', function (done) {
            const cache = createErrorCache();
            elbv2HttpsOnly.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
        
        it('should UNKNOWN if unable to describe load balancer listeners', function (done) {
            const cache = createCache([describeLoadBalancers[0]]);
            elbv2HttpsOnly.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
        
        it('should not return anything if describe load balancers response is not found', function (done) {
            const cache = createNullCache();
            elbv2HttpsOnly.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
