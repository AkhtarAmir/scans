var async = require('async');
var helpers = require(__dirname + '/../../../helpers/azure');

module.exports = function(collection, reliesOn, retries, callback) {
    if (!reliesOn['storageAccounts.listKeys']) return callback();

    var azureStorage = require('azure-storage');

    if (!collection['queueService']['listQueuesSegmented']) collection['queueService']['listQueuesSegmented'] = {};
    if (!collection['queueService']['getQueueAcl']) collection['queueService']['getQueueAcl'] = {};

    // Loop through regions and properties in reliesOn
    async.eachOf(reliesOn['storageAccounts.listKeys'], function(regionObj, region, cb) {
        collection['queueService']['listQueuesSegmented'][region] = {};
        collection['queueService']['getQueueAcl'][region] = {};

        async.eachOfLimit(regionObj, 5, function(subObj, resourceId, sCb) {
            collection['queueService']['listQueuesSegmented'][region][resourceId] = {};

            if (subObj && subObj.data && subObj.data.keys && subObj.data.keys[0] && subObj.data.keys[0].value) {
                // Extract storage account name from resourceId
                var storageAccountName = resourceId.substring(resourceId.lastIndexOf('/') + 1);
                var storageService = new azureStorage['QueueService'](storageAccountName, subObj.data.keys[0].value);

                helpers.makeCustomCollectorCall(storageService, 'listQueuesSegmented', null, retries, function(serviceErr, serviceResults) {
                    if (serviceErr || !serviceResults) {
                        collection['queueService']['listQueuesSegmented'][region][resourceId].err = (serviceErr || 'No data returned');
                        sCb();
                    } else {
                        collection['queueService']['listQueuesSegmented'][region][resourceId].data = serviceResults.entries;

                        // Add ACLs
                        async.eachLimit(serviceResults.entries, 10, function(entryObj, entryCb) {
                            var entryId = `${resourceId}/queueService/${entryObj.name}`;
                            collection['queueService']['getQueueAcl'][region][entryId] = {};

                            helpers.makeCustomCollectorCall(storageService, 'getQueueAcl', entryObj.name, retries, function(getErr, getData) {
                                if (getErr || !getData) {
                                    collection['queueService']['getQueueAcl'][region][entryId].err = (getErr || 'No data returned');
                                } else {
                                    collection['queueService']['getQueueAcl'][region][entryId].data = getData;
                                }
                                entryCb();
                            });
                        }, function() {
                            sCb();
                        });
                    }
                });
            } else {
                sCb();
            }
        }, function() {
            cb();
        });
    }, function() {
        callback();
    });
};