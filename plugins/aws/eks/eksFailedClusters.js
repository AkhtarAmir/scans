var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EKS Failed Clusters',
    category: 'EKS',
    description: 'Ensures that EKS clusters are not in Failed state.',
    more_info: 'EKS cluster should not be in failed state to operate efectively.',
    link: 'https://docs.aws.amazon.com/eks/latest/userguide/clusters.html',
    recommended_action: 'Delete or reinstate failed EKS clusters',
    apis: ['EKS:listClusters', 'EKS:describeCluster', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.eks, function(region, rcb) {
            var listClusters = helpers.addSource(cache, source,
                ['eks', 'listClusters', region]);

            if (!listClusters) return rcb();

            if (listClusters.err || !listClusters.data) {
                helpers.addResult(
                    results, 3,
                    `Unable to query for EKS clusters: ${helpers.addError(listClusters)}`, region);
                return rcb();
            }

            if(!listClusters.data.length){
                helpers.addResult(results, 0, 'No EKS clusters found', region);
                return rcb();
            }

            for (var clusterName of listClusters.data) {
                var describeCluster = helpers.addSource(cache, source,
                    ['eks', 'describeCluster', region, clusterName]);

                var resource = `arn:${awsOrGov}:eks:${region}:${accountId}:${cluster}/${clusterName}`;

                if (!describeCluster || describeCluster.err ||
                    !describeCluster.data || !describeCluster.data.cluster) {
                    helpers.addResult(
                        results, 3,
                        'Unable to describe EKS cluster: ' + helpers.addError(describeCluster),
                        region, resource);
                    continue;
                }

                var cluster = describeCluster.data.cluster; 
                if (cluster.status && cluster.status.toUpperCase() === 'FAILED') {
                    helpers.addResult(results, 2,
                        `EKS cluster "${cluster.name}" is in failed state`,
                        region, resource);
                } else {
                    helpers.addResult(results, 0,
                        `EKS cluster "${cluster.name}" is not in failed state`,
                        region, resource);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};