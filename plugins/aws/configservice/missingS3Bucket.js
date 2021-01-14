var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Missing S3 Bucket',
    category: 'ConfigService',
    description: 'Ensures that AWS Config Service delivery channels are using active S3 buckets.',
    more_info: 'AWS Config Service delivert channels should use active S3 bucket to save configuration information.',
    recommended_action: 'Create new S3 bucket and update bucket in delivery channel',
    link: 'https://docs.aws.amazon.com/config/latest/developerguide/manage-delivery-channel.html',
    apis: ['ConfigService:describeDeliveryChannels', 'S3:listBuckets'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var defaultRegion = helpers.defaultRegion(settings);
        var s3Buckets = [];

        var listBuckets = helpers.addSource(cache, source,
            ['s3', 'listBuckets', defaultRegion]);

        if (!listBuckets) return callback(null, results, source);

        if (listBuckets.err || !listBuckets.data) {
            helpers.addResult(results, 3,
                'Unable to query for S3 buckets: ' + helpers.addError(listBuckets));
            return callback(null, results, source);
        }

        if (listBuckets.data.length) {
            for (var bucket of listBuckets.data) {
                s3Buckets.push(bucket.Name);
            }
        }

        async.each(regions.configservice, function(region, rcb){
            var describeDeliveryChannels = helpers.addSource(cache, source,
                ['configservice', 'describeDeliveryChannels', region]);

            if (!describeDeliveryChannels) return rcb();

            if (describeDeliveryChannels.err || !describeDeliveryChannels.data) {
                helpers.addResult(results, 3,
                    'Unable to describe delivery channels: ' + helpers.addError(describeDeliveryChannels), region);
                return rcb();
            }

            if (!describeDeliveryChannels.data.length) {
                helpers.addResult(results, 0, 'No delivery channels found', region);
                return rcb();
            }

            for (var channel of describeDeliveryChannels.data) {
                var resource = channel.name;

                if (s3Buckets.includes(channel.s3BucketName)) {
                    helpers.addResult(results, 0,
                        `Delivery Channel ${channel.name} has active bucket configured`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `Delivery Channel ${channel.name} has missing bucket configured`,
                        region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};