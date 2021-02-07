var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'AWS ELB Security Group',
    category: 'ELB',
    description: 'Ensures that AWS ELBs have custom security group attached which allows public access to ports defined by listeners.',
    more_info: 'AWS ELBs should have active custom security group attached and allows public access to ports defined by listeners.',
    link: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-security-groups.html',
    recommended_action: 'Attach a custom security group to ELB or update custom security group and allow access to ports defined in ELB listeners',
    apis: ['ELB:describeLoadBalancers', 'EC2:describeSecurityGroups', 'STS:getCallerIdentity'],

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

            var describeSecurityGroups = helpers.addSource(cache, source,
                ['ec2', 'describeSecurityGroups', region]);

            if (!describeSecurityGroups || describeSecurityGroups.err || !describeSecurityGroups.data) {
                helpers.addResult(results, 3,
                    `Unable to describe security groups: ${helpers.addError(describeSecurityGroups)}`,
                    region);
                return rcb();
            }

            var sgMap = {};
            for (var sg of describeSecurityGroups.data) {
                if (sg.GroupName === 'default') continue;

                sgMap[sg.GroupId] = [];
                for (var perm of sg.IpPermissions) {
                    if (perm.FromPort && perm.ToPort) {
                        sgMap[sg.GroupId].push([perm.FromPort, perm.ToPort].join(':'));
                    } else {
                        sgMap[sg.GroupId].push([0, 65535].join(':'));
                    }
                }
            }

            for (var lb of describeLoadBalancers.data) {
                var resource = `arn:${awsOrGov}:elasticloadbalancing:${region}:${accountId}:loadbalancer/${lb.LoadBalancerName}`;

                var allowedPorts = false;

                if (!lb.ListenerDescriptions.length) {
                    helpers.addResult(results, 0,
                        `AWS ELB "${lb.LoadBalancerName}" does not have any listeners configured`,
                        region, resource);
                    continue;
                }

                for (var desc of lb.ListenerDescriptions) {
                    allowedPorts = false;
                    for (var group of lb.SecurityGroups) {
                        if (!sgMap[group]) continue;

                        for (var ports of sgMap[group]) {
                            ports = ports.split(':');
                            if (desc.Listener.InstancePort >= ports[0] && desc.Listener.InstancePort <= ports[1]) {
                                allowedPorts = true;
                                break;
                            }
                        }
                    }

                    if (!allowedPorts) {
                        break;
                    }
                }

                if (allowedPorts) {
                    helpers.addResult(results, 0,
                        `AWS ELB "${lb.LoadBalancerName}" associated security group(s) allow all listener ports`,
                        region, resource);        
                } else {
                    helpers.addResult(results, 2,
                        `AWS ELB "${lb.LoadBalancerName}" associated security group(s) do not allow all listener ports`,
                        region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};