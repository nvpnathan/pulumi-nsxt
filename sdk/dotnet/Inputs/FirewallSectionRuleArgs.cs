// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt.Inputs
{

    public sealed class FirewallSectionRuleArgs : Pulumi.ResourceArgs
    {
        [Input("action", required: true)]
        public Input<string> Action { get; set; } = null!;

        [Input("appliedTos")]
        private InputList<Inputs.FirewallSectionRuleAppliedToArgs>? _appliedTos;
        public InputList<Inputs.FirewallSectionRuleAppliedToArgs> AppliedTos
        {
            get => _appliedTos ?? (_appliedTos = new InputList<Inputs.FirewallSectionRuleAppliedToArgs>());
            set => _appliedTos = value;
        }

        [Input("description")]
        public Input<string>? Description { get; set; }

        [Input("destinations")]
        private InputList<Inputs.FirewallSectionRuleDestinationArgs>? _destinations;
        public InputList<Inputs.FirewallSectionRuleDestinationArgs> Destinations
        {
            get => _destinations ?? (_destinations = new InputList<Inputs.FirewallSectionRuleDestinationArgs>());
            set => _destinations = value;
        }

        [Input("destinationsExcluded")]
        public Input<bool>? DestinationsExcluded { get; set; }

        [Input("direction")]
        public Input<string>? Direction { get; set; }

        [Input("disabled")]
        public Input<bool>? Disabled { get; set; }

        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("id")]
        public Input<string>? Id { get; set; }

        [Input("ipProtocol")]
        public Input<string>? IpProtocol { get; set; }

        [Input("logged")]
        public Input<bool>? Logged { get; set; }

        [Input("notes")]
        public Input<string>? Notes { get; set; }

        [Input("revision")]
        public Input<int>? Revision { get; set; }

        [Input("ruleTag")]
        public Input<string>? RuleTag { get; set; }

        [Input("services")]
        private InputList<Inputs.FirewallSectionRuleServiceArgs>? _services;
        public InputList<Inputs.FirewallSectionRuleServiceArgs> Services
        {
            get => _services ?? (_services = new InputList<Inputs.FirewallSectionRuleServiceArgs>());
            set => _services = value;
        }

        [Input("sources")]
        private InputList<Inputs.FirewallSectionRuleSourceArgs>? _sources;
        public InputList<Inputs.FirewallSectionRuleSourceArgs> Sources
        {
            get => _sources ?? (_sources = new InputList<Inputs.FirewallSectionRuleSourceArgs>());
            set => _sources = value;
        }

        [Input("sourcesExcluded")]
        public Input<bool>? SourcesExcluded { get; set; }

        public FirewallSectionRuleArgs()
        {
        }
    }
}
