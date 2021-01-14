var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Include Global Resources',
    category: 'ConfigService',
    description: 'Ensures that AWS Config Service is configured to include global resources.',
    more_info: 'AWS Config Service is configured to include global resources to record configuration changes made within AWS account.',
    recommended_action: 'Update AWS Config Service settings to include global resources',
    link: 'https://aws.amazon.com/config/details/',
    apis: ['ConfigService:describeConfigurationRecorders'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.configservice, function(region, rcb){
            var describeConfigurationRecorders = helpers.addSource(cache, source,
                ['configservice', 'describeConfigurationRecorders', region]);

            if (!describeConfigurationRecorders) return rcb();

            if (describeConfigurationRecorders.err || !describeConfigurationRecorders.data) {
                helpers.addResult(results, 3,
                    'Unable to describe configuration recorders: ' + helpers.addError(describeConfigurationRecorders), region);
                return rcb();
            }

            if (!describeConfigurationRecorders.data.length) {
                helpers.addResult(results, 0, 'No configuration recorders found', region);
                return rcb();
            }

            for (var configuration of describeConfigurationRecorders.data) {
                if (configuration.recordingGroup && configuration.recordingGroup.includeGlobalResourceTypes) {
                    helpers.addResult(results, 0,
                        'AWS Config is configured to include Global resources', region);
                } else {
                    helpers.addResult(results, 2,
                        'AWS Config is not configured to include Global resources', region);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};