var async = require('async');
var helpers = require('../../../helpers/aws');

var filterPatterns = [    
    {
        name: 'Root Account Usage',
        pattern: '{ $.userIdentity.type = Root && $.userIdentity.invokedBy NOT EXISTS && $.eventType != AwsServiceEvent }'
    }
];

module.exports = {
    title: 'CloudWatch Monitoring Metrics',
    category: 'CloudWatchLogs',
    description: 'Ensures metric filters are setup for CloudWatch logs to detect security risks from CloudTrail.',
    more_info: 'Sending CloudTrail logs to CloudWatch is only useful if metrics are setup to detect risky activity from those logs. There are numerous metrics that should be used. For the exact filter patterns, please see this plugin on GitHub: https://github.com/cloudsploit/scans/blob/master/plugins/aws/cloudwatchlogs/monitoringMetrics.js',
    recommended_action: 'Enable metric filters to detect malicious activity in CloudTrail logs sent to CloudWatch.',
    link: 'http://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html',
    apis: ['CloudTrail:describeTrails', 'CloudWatchLogs:describeMetricFilters'],
    compliance: {
        cis1: '3.3 Ensure a log metric filter and alarm exist for usage of root account'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.cloudtrail, function(region, rcb){
            var describeTrails = helpers.addSource(cache, source,
                ['cloudtrail', 'describeTrails', region]);

            if (!describeTrails || describeTrails.err ||
                !describeTrails.data || !describeTrails.data.length) {
                return rcb();
            }

            var trailsInRegion = [];

            for (var t in describeTrails.data) {
                if (describeTrails.data[t].HomeRegion &&
                    describeTrails.data[t].HomeRegion === region) {
                    trailsInRegion.push(describeTrails.data[t]);
                }
            }

            if (!trailsInRegion.length) return rcb();

            var describeMetricFilters = helpers.addSource(cache, source,
                ['cloudwatchlogs', 'describeMetricFilters', region]);

            if (!describeMetricFilters ||
                describeMetricFilters.err || !describeMetricFilters.data) {
                helpers.addResult(results, 3,
                    'Unable to query for CloudWatchLogs metric filters: ' + helpers.addError(describeMetricFilters), region);

                return rcb();
            }

            if (!describeMetricFilters.data.length) {
                helpers.addResult(results, 2,
                    'There are no CloudWatch metric filters in this region', region);

                return rcb();
            }

            // Organize filters by log group name
            var filters = {};

            for (var f in describeMetricFilters.data) {
                var filter = describeMetricFilters.data[f];

                if (filter.logGroupName && filter.filterPattern) {
                    if (!filters[filter.logGroupName]) filters[filter.logGroupName] = [];
                    filters[filter.logGroupName].push(filter.filterPattern.replace(/\s+/g, '').toLowerCase());
                }
            }

            async.each(trailsInRegion, function(trail, tcb){
                if (!trail.CloudWatchLogsLogGroupArn) return tcb();

                // CloudTrail stores the CloudWatch Log Group as a full ARN
                // while CloudWatch Logs just stores the group name.
                // Need to filter the name out for comparison.
                var startPos = trail.CloudWatchLogsLogGroupArn.indexOf('log-group:') + 10;
                var endPos = trail.CloudWatchLogsLogGroupArn.lastIndexOf(':');
                var logGroupName = trail.CloudWatchLogsLogGroupArn.substring(startPos, endPos);

                if (!filters[logGroupName]) {
                    helpers.addResult(results, 2,
                        'There are no CloudWatch metric filters for this trail', region,
                        trail.TrailARN);

                    return tcb();
                }

                var missing = [];

                // If there is a filter setup, check for all strings.
                for (var p in filterPatterns) {
                    var found = false;
                    var pattern = filterPatterns[p];
                    var patternSearch = pattern.pattern.replace(/\s+/g, '').toLowerCase();

                    for (var f in filters) {
                        var filter = filters[f];

                        if (filter.indexOf(patternSearch) > - 1) {
                            found = true;
                            break;
                        }
                    }

                    if (!found) {
                        missing.push(pattern.name);
                    }
                }

                if (missing.length) {
                    helpers.addResult(results, 2,
                        'Trail logs are missing filters for: ' + missing.join(', '), region,
                        trail.TrailARN);
                } else {
                    helpers.addResult(results, 0,
                        'Trail logs have filter patterns for all required metrics', region,
                        trail.TrailARN);
                }

                tcb();
            }, function(){
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};
