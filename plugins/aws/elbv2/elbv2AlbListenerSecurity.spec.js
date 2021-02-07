var expect = require('chai').expect;
const elbv2AlbListenerSecurity = require('./elbv2AlbListenerSecurity');

const describeLoadBalancers = [
    {
        "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/akd-47/870c3de5e268670e",
        "DNSName": "akd-47-2038106393.us-east-1.elb.amazonaws.com",
        "CanonicalHostedZoneId": "Z35SXDOTRQ7X7K",
        "CreatedTime": "2021-02-07T13:51:27.440000+00:00",
        "LoadBalancerName": "akd-47",
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
            "sg-aa941691",
            "sg-001639e564442dfec"
        ],
        "IpAddressType": "ipv4"
    },
    {
        "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/akd-47/870c3de5e268670e",
        "DNSName": "akd-47-2038106393.us-east-1.elb.amazonaws.com",
        "CanonicalHostedZoneId": "Z35SXDOTRQ7X7K",
        "CreatedTime": "2021-02-07T13:51:27.440000+00:00",
        "LoadBalancerName": "akd-47",
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
            "sg-aa941691",
            "sg-001639e564442dfec"
        ],
        "IpAddressType": "ipv4"
    }
];

const describeListeners = [
    {
        "Listeners": [
            {
                "ListenerArn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:listener/app/akd-47/870c3de5e268670e/27a75edb111bcf9b",
                "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/akd-47/870c3de5e268670e",
                "Port": 80,
                "Protocol": "HTTPS",
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
            }
        ]
    },
    {
        "Listeners": [
            {
                "ListenerArn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:listener/app/akd-47/870c3de5e268670e/27a75edb111bcf9b",
                "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/akd-47/870c3de5e268670e",
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
            }
        ]
    }
];

const createCache = (describeLoadBalancers, describeListeners, describeLoadBalancersErr, describeListenersErr) => {
    var dnsName = (describeLoadBalancers && describeLoadBalancers.length) ? describeLoadBalancers[0].DNSName : null;

    return {
        elbv2: {
            describeLoadBalancers: {
                'us-east-1': {
                    err: describeLoadBalancersErr,
                    data: describeLoadBalancers
                }
            },
            describeListeners: {
                'us-east-1': {
                    [dnsName]: {
                        err: describeListenersErr,
                        data: describeListeners
                    }
                }
            }
        },
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

describe('elbv2AlbListenerSecurity', function () {
    describe('run', function () {
        it('should PASS if AWS application load balancer has secured listener configured', function (done) {
            const cache = createCache([describeLoadBalancers[0]], describeListeners[0]);
            elbv2AlbListenerSecurity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if AWS application load balancer does not secured listener configured', function (done) {
            const cache = createCache([describeLoadBalancers[0]], describeListeners[1]);
            elbv2AlbListenerSecurity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if No application load balancer listeners found', function (done) {
            const cache = createCache([describeLoadBalancers[0]], []);
            elbv2AlbListenerSecurity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if No ELBv2 load balancers found', function (done) {
            const cache = createCache([]);
            elbv2AlbListenerSecurity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if No application load balancers found', function (done) {
            const cache = createCache([describeLoadBalancers[1]], describeListeners[1]);
            elbv2AlbListenerSecurity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to query for ELBv2 load balancers', function (done) {
            const cache = createCache([describeLoadBalancers[0]], describeListeners[0], { message: 'Unable to query for load balancers' });
            elbv2AlbListenerSecurity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to query for application load balancer listeners', function (done) {
            const cache = createCache([describeLoadBalancers[0]], describeListeners[0], null, { message: 'Unable to query for application load balancer listeners' });
            elbv2AlbListenerSecurity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should not return anything if describe load balancers response is not found', function (done) {
            const cache = createNullCache();
            elbv2AlbListenerSecurity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
}); 