var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudFormation Stack IAM Role',
    category: 'CloudFormation',
    description: 'Ensures that AWS CloudFormation stacks have IAM role associated.',
    more_info: 'AWS CloudFormation stacks should have IAM role associated to avoid previlege escalation.',
    link: 'https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-servicerole.html',
    recommended_action: 'Update the stack and attach IAM role',
    apis: ['CloudFormation:listStacks', 'CloudFormation:describeStacks'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.cloudformation, function(region, rcb){
            var listStacks = helpers.addSource(cache, source,
                ['cloudformation', 'listStacks', region]);

            if (!listStacks) return rcb();

            if (listStacks.err || !listStacks.data) {
                helpers.addResult(results, 3, `Unable to query for CloudFormation stacks: ${helpers.addError(listStacks)}`, region);
                return rcb();
            }

            if (!listStacks.data.length) {
                helpers.addResult(results, 0, 'No CloudFormation stacks found', region);
                return rcb();
            }

            async.each(listStacks.data, function(stack, cb){
                if (!stack.StackId || !stack.StackName) return cb();

                var describeStacks = helpers.addSource(cache, source,
                    ['cloudformation', 'describeStacks', region, stack.StackName]);

                if (!describeStacks || describeStacks.err || !describeStacks.data ||
                    !describeStacks.data.Stacks || !describeStacks.data.Stacks.length) {
                    helpers.addResult(results, 3, `Unable to query for CloudFormation stack details: ${helpers.addError(describeStacks)}`,
                        region, stack.StackId);
                    return cb();
                }

                for (var stackDetails of describeStacks.data.Stacks) {
                    var resource = stackDetails.StackId;

                    if (stackDetails.RoleARN) {
                        helpers.addResult(results, 0,
                            `CloudFormation stack "${stackDetails.StackName}" has IAM role associated`,
                            region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            `CloudFormation stack "${stackDetails.StackName}" does not have IAM role associated`,
                            region, resource);
                    }
                }

                cb();
            }, function(){
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};