var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var ses = new AWS.SES(AWSConfig);

    async.eachLimit(collection.ses.listIdentities[AWSConfig.region].data, 1, function(identityName, cb){
        setTimeout(function() {
            cb();
        }, 1000);
        collection.ses.listIdentityPolicies[AWSConfig.region][identityName] = {};
        var params = {
            'Identity': identityName
        };

        ses.listIdentityPolicies(params, function(err, data) {
            if (err) {
                collection.ses.listIdentityPolicies[AWSConfig.region][identityName].err = err;
            }
            collection.ses.listIdentityPolicies[AWSConfig.region][identityName].data = data;
            cb();
        });
    }, function(){
        callback();
    });
};
