const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Application Whitelisting Enabled',
    category: 'Security Center',
    description: 'Ensures that Security Center Monitor Adaptive Application Whitelisting is enabled',
    more_info: 'Adaptive application controls work in conjunction with machine learning to analyze processes running in a VM and help control which applications can run, hardening the VM against malware.',
    recommended_action: 'Enable Adaptive Application Controls for Virtual Machines from the Azure Security Center by ensuring AuditIfNotExists setting is used.',
    link: 'https://docs.microsoft.com/en-us/azure/security-center/security-center-adaptiveapplication',
    apis: ['policyAssignments:list'],
    compliance: {
        cis1: '2.13 Ensure ASC Default policy setting "Monitor Adaptive Application Whitelisting" ' +
		'is not "Disabled"'
    },

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.policyAssignments, function(location, rcb) {
            const policyAssignments = helpers.addSource(
                cache, source, ['policyAssignments', 'list', location]
            );

            helpers.checkPolicyAssignment(policyAssignments,
                'adaptiveApplicationControlsMonitoringEffect',
                'Monitor Adaptive Application Whitelisting', results, location);

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
