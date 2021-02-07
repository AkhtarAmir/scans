var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ELBv2 ALB Listener Security',
    category: 'ELBv2',
    description: 'Ensures that AWS Application Load Balancers have secured listener configured.',
    more_info: 'AWS Application Load Balancer should have HTTPS protocol listener configured to terminate TLS traffic.',
    link: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html',
    recommended_action: 'Attach HTTPS listener to AWS Application Load Balancer',
    apis: ['ELBv2:describeLoadBalancers', 'ELBv2:describeListeners'],

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
                    `Unable to query for Application Load Balancers: ${helpers.addError(describeLoadBalancers)}`,
                    region);
                return rcb();
            }

            if (!describeLoadBalancers.data.length) {
                helpers.addResult(results, 0, 'No Load Balancers found', region);
                return rcb();
            }

            var applicationElbFound = false;
            async.each(describeLoadBalancers.data, function(elb, cb){
                if (elb.Type && elb.Type === 'application') {
                    applicationElbFound = true;
                    var securedListenerFound = false;
                    var resource = elb.LoadBalancerArn;

                    var describeListeners = helpers.addSource(cache, source,
                        ['elbv2', 'describeListeners', region, elb.DNSName]);

                    if (!describeListeners || describeListeners.err || !describeListeners.data) {
                        helpers.addResult(results, 3,
                            `Unable to query for Application Load Balancer listeners: ${helpers.addError(describeListeners)}`,
                            region, resource);
                        return cb();
                    }

                    if(!describeListeners.data.Listeners || !describeListeners.data.Listeners.length){
                        helpers.addResult(results, 0,
                            'No Application Load Balancer listeners found',
                            region, resource);
                        return cb();
                    }

                    for (var listener of describeListeners.data.Listeners) {
                        if(listener.Protocol && listener.Protocol === 'HTTPS') {
                            securedListenerFound = true;
                            break;
                        }
                    }

                    if(securedListenerFound) {
                        helpers.addResult(results, 0,
                            `Application Load Balancer "${elb.LoadBalancerName}" has secure listener configured`,
                            region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            `Application Load Balancer "${elb.LoadBalancerName}" does not have secure listener configured`,
                            region, resource);
                    }
                }

                cb();
            }, function(){
                if (!applicationElbFound) {
                    helpers.addResult(results, 0,
                        'No Application Load Balancers found', region);
                }
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};