// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt.Inputs
{

    public sealed class PolicySecurityPolicyRuleArgs : Pulumi.ResourceArgs
    {
        [Input("action")]
        public Input<string>? Action { get; set; }

        [Input("description")]
        public Input<string>? Description { get; set; }

        [Input("destinationGroups")]
        private InputList<string>? _destinationGroups;
        public InputList<string> DestinationGroups
        {
            get => _destinationGroups ?? (_destinationGroups = new InputList<string>());
            set => _destinationGroups = value;
        }

        [Input("destinationsExcluded")]
        public Input<bool>? DestinationsExcluded { get; set; }

        [Input("direction")]
        public Input<string>? Direction { get; set; }

        [Input("disabled")]
        public Input<bool>? Disabled { get; set; }

        [Input("displayName", required: true)]
        public Input<string> DisplayName { get; set; } = null!;

        [Input("ipVersion")]
        public Input<string>? IpVersion { get; set; }

        [Input("logLabel")]
        public Input<string>? LogLabel { get; set; }

        [Input("logged")]
        public Input<bool>? Logged { get; set; }

        [Input("notes")]
        public Input<string>? Notes { get; set; }

        [Input("nsxId")]
        public Input<string>? NsxId { get; set; }

        [Input("profiles")]
        private InputList<string>? _profiles;
        public InputList<string> Profiles
        {
            get => _profiles ?? (_profiles = new InputList<string>());
            set => _profiles = value;
        }

        [Input("revision")]
        public Input<int>? Revision { get; set; }

        [Input("ruleId")]
        public Input<int>? RuleId { get; set; }

        [Input("scopes")]
        private InputList<string>? _scopes;
        public InputList<string> Scopes
        {
            get => _scopes ?? (_scopes = new InputList<string>());
            set => _scopes = value;
        }

        [Input("sequenceNumber")]
        public Input<int>? SequenceNumber { get; set; }

        [Input("services")]
        private InputList<string>? _services;
        public InputList<string> Services
        {
            get => _services ?? (_services = new InputList<string>());
            set => _services = value;
        }

        [Input("sourceGroups")]
        private InputList<string>? _sourceGroups;
        public InputList<string> SourceGroups
        {
            get => _sourceGroups ?? (_sourceGroups = new InputList<string>());
            set => _sourceGroups = value;
        }

        [Input("sourcesExcluded")]
        public Input<bool>? SourcesExcluded { get; set; }

        [Input("tags")]
        private InputList<Inputs.PolicySecurityPolicyRuleTagArgs>? _tags;
        public InputList<Inputs.PolicySecurityPolicyRuleTagArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.PolicySecurityPolicyRuleTagArgs>());
            set => _tags = value;
        }

        public PolicySecurityPolicyRuleArgs()
        {
        }
    }
}
