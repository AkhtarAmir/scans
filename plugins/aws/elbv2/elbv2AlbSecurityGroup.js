var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ELBv2 ALB Security Group',
    category: 'ELBv2',
    description: 'Ensures that AWS application load balancers have custom security group attached which allows public access to ports defined by listeners.',
    more_info: 'AWS application load balancers should have active custom security group attached and allows public access to ports defined by listeners.',
    link: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-update-security-groups.html',
    recommended_action: 'Attach a custom security group to application load balancer or update custom security group and allow access to ports defined in listeners',
    apis: ['ELBv2:describeLoadBalancers', 'ELBv2:describeListeners', 'EC2:describeSecurityGroups'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.elbv2, function(region, rcb){
            var describeLoadBalancers = helpers.addSource(cache, source,
                ['elbv2', 'describeLoadBalancers', region]);

            if (!describeLoadBalancers) return rcb();

            if (describeLoadBalancers.err || !describeLoadBalancers.data) {
                helpers.addResult(results, 3,
                    `Unable to query for ELBv2 load balancers: ${helpers.addError(describeLoadBalancers)}`, region);
                return rcb();
            }

            if (!describeLoadBalancers.data.length) {
                helpers.addResult(results, 0, 'No ELBv2 load balancers found', region);
                return rcb();
            }

            var describeSecurityGroups = helpers.addSource(cache, source,
                ['ec2', 'describeSecurityGroups', region]);

            if (!describeSecurityGroups || describeSecurityGroups.err || !describeSecurityGroups.data) {
                helpers.addResult(results, 3,
                    `Unable to query for security groups: ${helpers.addError(describeSecurityGroups)}`,
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

            var applicationElbFound = false;
            async.each(describeLoadBalancers.data, function(lb, lcb){
                if (lb.Type && lb.Type === 'application') {
                    applicationElbFound = true;
                    var resource = lb.LoadBalancerArn;
    
                    var describeListeners = helpers.addSource(cache, source,
                        ['elbv2', 'describeListeners', region, lb.DNSName]);
    
                    if (!describeListeners || describeListeners.err || !describeListeners.data || !describeListeners.data.Listeners) {
                        helpers.addResult(results, 3,
                            `Unable to query for application load balancer listeners for "${lb.LoadBalancerName}": ${helpers.addError(describeListeners)}`,
                            region, resource);
                        return lcb();
                    }
    
                    if (!describeListeners.data.Listeners.length) {
                        helpers.addResult(results, 0,
                            `AWS application load balancer "${lb.LoadBalancerName}" does not have any listeners configured`,
                            region, resource);
                        return lcb();
                    }
    
                    var allowedPorts = false;
                    for (var listener of describeListeners.data.Listeners) {
                        allowedPorts = false;
    
                        for (var group of lb.SecurityGroups) {
                            if (!sgMap[group]) continue;
    
                            for (var ports of sgMap[group]) {
                                ports = ports.split(':');
                                if (listener.Port >= ports[0] && listener.Port <= ports[1]) {
                                    allowedPorts = true;
                                    break;
                                }
                            }
                        }
    
                        if (!allowedPorts) break;
                    }
    
                    if (allowedPorts) {
                        helpers.addResult(results, 0,
                            `AWS application load balancer "${lb.LoadBalancerName}" associated security group(s) allow all listener ports`,
                            region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            `AWS application load balancer "${lb.LoadBalancerName}" associated security group(s) do not allow all listener ports`,
                            region, resource);
                    }
                }

                lcb();
            }, function() {
                if (!applicationElbFound) {
                    helpers.addResult(results, 0,
                        `No application load balancer found`, region);
                }
                rcb();
            });
        }, function(){
                callback(null, results, source);
        });
    }
};