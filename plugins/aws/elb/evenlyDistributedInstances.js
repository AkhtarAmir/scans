var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ELB Evenly Distributed Instances Across AZs',
    category: 'ELB',
    description: 'Ensures that AWS ELBs have evenly distributed instances across Availability Zones.',
    more_info: 'AWS ELBs should have evenly distributed instances accross availability zones to ensure the ELB availability and reliability.',
    link: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-subnets.html',
    recommended_action: 'Update AWS ELB and include availability zones or move instances to other ELBs',
    apis: ['ELB:describeLoadBalancers', 'ELB:describeLoadBalancerAttributes', 'EC2:describeInstances', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.elb, function(region, rcb){
            var describeLoadBalancers = helpers.addSource(cache, source,
                ['elb', 'describeLoadBalancers', region]);

            if (!describeLoadBalancers) return rcb();

            if (describeLoadBalancers.err || !describeLoadBalancers.data) {
                helpers.addResult(results, 3,
                    `Unable to query for load balancers: ${helpers.addError(describeLoadBalancers)}`, region);
                return rcb();
            }

            if (!describeLoadBalancers.data.length) {
                helpers.addResult(results, 0, 'No load balancers found', region);
                return rcb();
            }

            var describeInstances = helpers.addSource(cache, source,
                ['ec2', 'describeInstances', region]);

            if (!describeInstances || describeInstances.err || !describeInstances.data) {
                helpers.addResult(results, 3,
                    `Unable to query for EC2 instances: ${helpers.addError(describeInstances)}`, region);
                return rcb();
            }

            var instanceAZs = {};
            for (var instances of describeInstances.data) {
                for (var instance of instances.Instances) {
                    if (instance.Placement.AvailabilityZone) {
                        instanceAZs[instance.InstanceId] = instance.Placement.AvailabilityZone;
                    }
                }
            }            

            async.each(describeLoadBalancers.data, function(lb, cb){
                var resource = `arn:${awsOrGov}:elasticloadbalancing:${region}:${accountId}:loadbalancer/${lb.LoadBalancerName}`;

                var describeLoadBalancerAttributes = helpers.addSource(cache, source,
                    ['elb', 'describeLoadBalancerAttributes', region, lb.DNSName]);

                if (!describeLoadBalancerAttributes ||
                    describeLoadBalancerAttributes.err ||
                    !describeLoadBalancerAttributes.data || 
                    !describeLoadBalancerAttributes.data.LoadBalancerAttributes) {
                    helpers.addResult(results, 3,
                        `Unable to query for load balancer attributes: ${helpers.addError(describeLoadBalancerAttributes)}`,
                        region, resource);
                    return cb();
                }

                if (describeLoadBalancerAttributes.data.LoadBalancerAttributes.CrossZoneLoadBalancing &&
                    describeLoadBalancerAttributes.data.LoadBalancerAttributes.CrossZoneLoadBalancing.Enabled) {
                    var instancesCount = {};
                    var multiAzFound = false;

                    for (var instance of lb.Instances) {
                        availabilityZone = instanceAZs[instance.InstanceId];
                        if (instancesCount[availabilityZone]) {
                            multiAzFound = true;
                            instancesCount[availabilityZone] = instancesCount[availabilityZone] + 1
                        } else {
                            instancesCount[availabilityZone] = 1;
                        }
                    }

                    if (!multiAzFound) {
                        helpers.addResult(results, 0,
                            `AWS ELB "${lb.LoadBalancerName}" has evenly distributed instances across availability zones`,
                            region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            `AWS ELB "${lb.LoadBalancerName}" does not have evenly distributed instances across ${JSON.stringify(instancesCount)} availability zones`,
                            region, resource);
                    }
                } else {
                    helpers.addResult(results, 2,
                        `AWS ELB "${lb.LoadBalancerName}" does not have cross zone load balancing enabled`,
                        region, resource);
                }

                cb();
            }, function(){
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};
