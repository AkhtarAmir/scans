// TODO: MOVE TO EC2
var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: '',
    category: '',
    description: '',
    more_info: '',
    link: '',
    recommended_action: '',
    apis: ['EC2:describeInstances'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.ec2, function(region, rcb){
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
