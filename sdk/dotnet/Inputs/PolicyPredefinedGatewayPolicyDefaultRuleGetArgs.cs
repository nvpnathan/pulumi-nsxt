// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt.Inputs
{

    public sealed class PolicyPredefinedGatewayPolicyDefaultRuleGetArgs : Pulumi.ResourceArgs
    {
        [Input("action")]
        public Input<string>? Action { get; set; }

        [Input("description")]
        public Input<string>? Description { get; set; }

        [Input("logLabel")]
        public Input<string>? LogLabel { get; set; }

        [Input("logged")]
        public Input<bool>? Logged { get; set; }

        [Input("nsxId")]
        public Input<string>? NsxId { get; set; }

        [Input("path")]
        public Input<string>? Path { get; set; }

        [Input("revision")]
        public Input<int>? Revision { get; set; }

        [Input("scope", required: true)]
        public Input<string> Scope { get; set; } = null!;

        [Input("sequenceNumber")]
        public Input<int>? SequenceNumber { get; set; }

        [Input("tags")]
        private InputList<Inputs.PolicyPredefinedGatewayPolicyDefaultRuleTagGetArgs>? _tags;
        public InputList<Inputs.PolicyPredefinedGatewayPolicyDefaultRuleTagGetArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.PolicyPredefinedGatewayPolicyDefaultRuleTagGetArgs>());
            set => _tags = value;
        }

        public PolicyPredefinedGatewayPolicyDefaultRuleGetArgs()
        {
        }
    }
}
