var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'AWS Glue Data Catalog Encryption At Rest',
    category: 'AWS Glue',
    description: 'Ensure that Amazon Glue Data Catalog objects and connection passwords are encrypted.',
    more_info: 'AWS Glue should have encryption at-rest enabled for Glue Data Catalog objects and connection passwords to ensure security of sensitive data.',
    recommended_action: 'Enable Metadata encryption in AWS Glue catalog settings',
    link: 'https://docs.aws.amazon.com/glue/latest/dg/encrypt-glue-data-catalog.html',
    apis: ['Glue:getDataCatalogEncryptionSettings', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.glue, function(region, rcb){
            var getDataCatalogEncryptionSettings = helpers.addSource(cache, source,
                ['glue', 'getDataCatalogEncryptionSettings', region]);
            
            if (!getDataCatalogEncryptionSettings) return rcb();

            if (getDataCatalogEncryptionSettings.err) {
                helpers.addResult(results, 3,
                    `Unable to query for AWS Glue data catalog encryption settings: ${helpers.addError(getDataCatalogEncryptionSettings)}`, region);
                return rcb();
            }

            if (!getDataCatalogEncryptionSettings.data) {
                helpers.addResult(results, 0,
                    'No AWS Glue data catalog encryption settings found', region);
                return rcb();
            }

            var catalogSettings = getDataCatalogEncryptionSettings.data;
            var resource = `arn:${awsOrGov}:glue:${region}:${accountId}:/catalog/settings`;

            if(!catalogSettings.EncryptionAtRest || !catalogSettings.EncryptionAtRest.CatalogEncryptionMode ||
                catalogSettings.EncryptionAtRest.CatalogEncryptionMode.toUpperCase() === 'DISABLED') {
                helpers.addResult(results, 2,
                    `AWS Glue data catalog encryption settings has encryption at rest disabled`,
                    region, resource);
            } else {
                helpers.addResult(results, 0,
                    `AWS Glue data catalog encryption settings has encryption at rest enabled`,
                    region, resource);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};