var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Unused Customer Master Key',
    category: 'KMS',
    description: 'Ensures that there are no KMS Customer Master Keys in disabled state.',
    more_info: 'Disabled KMS Customer Master Keys should be deleted to avoid extra billing as disabled keys are also charged.',
    recommended_action: 'Schedule KMS Customer Master Key deletion for disabled KMS keys',
    link: 'http://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html',
    apis: ['KMS:listKeys', 'KMS:describeKey'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.kms, function(region, rcb){
            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys) return rcb();

            if (listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }

            if (!listKeys.data.length) {
                helpers.addResult(results, 0, 'No KMS keys found', region);
                return rcb();                
            }

            var cmkFound = false;
            async.each(listKeys.data, function(kmsKey, kcb){
                var describeKey = helpers.addSource(cache, source,
                    ['kms', 'describeKey', region, kmsKey.KeyId]);

                if (!describeKey || describeKey.err || !describeKey.data) {
                    helpers.addResult(results, 3,
                        `Unable to describe key: ${helpers.addError(describeKey)}`,
                        region, kmsKey.KeyArn);
                    return kcb();
                }

                var describeKeyData = describeKey.data;

                // AWS-generated keys should be skipped. The only way to distinguish these keys is the default description used by AWS.
                if (describeKeyData.KeyMetadata && (describeKeyData.KeyMetadata.Description &&
                        describeKeyData.KeyMetadata.Description.indexOf('Default master key that protects my') === 0)) {
                    return kcb();
                }

                cmkFound = true;
                if (describeKeyData && describeKeyData.KeyMetadata &&
                    describeKeyData.KeyMetadata.Enabled &&
                    describeKeyData.KeyMetadata.Enabled === true) {
                    helpers.addResult(results, 0,
                        `KMS Customer Master Key "${kmsKey.KeyId}" is enabled`, region, kmsKey.KeyArn);
                } else {
                    helpers.addResult(results, 2,
                        `KMS Customer Master Key "${kmsKey.KeyId}" is disabled`, region, kmsKey.KeyArn);
                }

                kcb();
            }, function(){
                if(!cmkFound) {
                    helpers.addResult(results, 0,
                        'No KMS Customer Master Keys found', region);
                }
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};