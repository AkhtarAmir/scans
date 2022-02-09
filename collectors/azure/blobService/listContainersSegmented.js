var async = require('async');
var helpers = require(__dirname + '/../../../helpers/azure');

module.exports = function(collection, reliesOn, retries, callback) {
    if (!reliesOn['storageAccounts.listKeys']) return callback();

    var azureStorage = require('azure-storage');

    if (!collection['blobService']['listContainersSegmented']) collection['blobService']['listContainersSegmented'] = {};
    if (!collection['blobService']['getContainerAcl']) collection['blobService']['getContainerAcl'] = {};

    // Loop through regions and properties in reliesOn
    async.eachOf(reliesOn['storageAccounts.listKeys'], function(regionObj, region, cb) {
        collection['blobService']['listContainersSegmented'][region] = {};
        collection['blobService']['getContainerAcl'][region] = {};

        async.eachOfLimit(regionObj, 5, function(subObj, resourceId, sCb) {
            collection['blobService']['listContainersSegmented'][region][resourceId] = {};

            if (subObj && subObj.data && subObj.data.keys && subObj.data.keys[0] && subObj.data.keys[0].value) {
                // Extract storage account name from resourceId
                var storageAccountName = resourceId.substring(resourceId.lastIndexOf('/') + 1);
                var storageService = new azureStorage['BlobService'](storageAccountName, subObj.data.keys[0].value);

                helpers.makeCustomCollectorCall(storageService, 'listContainersSegmented', null, retries, function(serviceErr, serviceResults) {
                    if (serviceErr || !serviceResults) {
                        collection['blobService']['listContainersSegmented'][region][resourceId].err = (serviceErr || 'No data returned');
                        sCb();
                    } else {
                        collection['blobService']['listContainersSegmented'][region][resourceId].data = serviceResults.entries;

                        // Add ACLs
                        async.eachLimit(serviceResults.entries, 10, function(entryObj, entryCb) {
                            var entryId = `${resourceId}/blobService/${entryObj.name}`;
                            collection['blobService']['getContainerAcl'][region][entryId] = {};

                            helpers.makeCustomCollectorCall(storageService, 'getContainerAcl', entryObj.name, retries, function(getErr, getData) {
                                if (getErr || !getData) {
                                    collection['blobService']['getContainerAcl'][region][entryId].err = (getErr || 'No data returned');
                                } else {
                                    collection['blobService']['getContainerAcl'][region][entryId].data = getData;
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