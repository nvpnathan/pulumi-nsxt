// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt.Outputs
{

    [OutputType]
    public sealed class PolicyPredefinedGatewayPolicyDefaultRule
    {
        public readonly string? Action;
        public readonly string? Description;
        public readonly string? LogLabel;
        public readonly bool? Logged;
        public readonly string? NsxId;
        public readonly string? Path;
        public readonly int? Revision;
        public readonly string Scope;
        public readonly int? SequenceNumber;
        public readonly ImmutableArray<Outputs.PolicyPredefinedGatewayPolicyDefaultRuleTag> Tags;

        [OutputConstructor]
        private PolicyPredefinedGatewayPolicyDefaultRule(
            string? action,

            string? description,

            string? logLabel,

            bool? logged,

            string? nsxId,

            string? path,

            int? revision,

            string scope,

            int? sequenceNumber,

            ImmutableArray<Outputs.PolicyPredefinedGatewayPolicyDefaultRuleTag> tags)
        {
            Action = action;
            Description = description;
            LogLabel = logLabel;
            Logged = logged;
            NsxId = nsxId;
            Path = path;
            Revision = revision;
            Scope = scope;
            SequenceNumber = sequenceNumber;
            Tags = tags;
        }
    }
}
