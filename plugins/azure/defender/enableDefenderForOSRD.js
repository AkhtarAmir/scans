var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Enable Defender For Open Source Relational Databases',
    category: 'Defender',
    domain: 'Management and Governance',
    description: 'Ensures that Microsoft Defender is enabled for Open Source Relational Databases.',
    more_info: 'Enabling Defender for Cloud on Open Source Relational Databases allows detection of unusual database access, query patterns, and suspicious activities, enhancing overall security.',
    recommended_action: 'Enable Microsoft Defender for Open Source Relational Databases in Defender plans for the subscription.',
    link: 'https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-security#microsoft-defender-for-cloud-support',
    apis: ['pricings:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.pricings, function(location, rcb) {
            var pricings = helpers.addSource(cache, source,
                ['pricings', 'list', location]);

            if (!pricings) return rcb();

            if (pricings.err || !pricings.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Pricing: ' + helpers.addError(pricings), location);
                return rcb();
            }

            if (!pricings.data.length) {
                helpers.addResult(results, 0, 'No Pricing information found', location);
                return rcb();
            }

            helpers.checkMicrosoftDefender(pricings, 'opensourcerelationaldatabases', 'Open Source Relational Databases', results, location);

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};