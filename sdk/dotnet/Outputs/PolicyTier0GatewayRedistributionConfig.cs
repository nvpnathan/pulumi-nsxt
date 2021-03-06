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
    public sealed class PolicyTier0GatewayRedistributionConfig
    {
        public readonly bool? Enabled;
        public readonly ImmutableArray<Outputs.PolicyTier0GatewayRedistributionConfigRule> Rules;

        [OutputConstructor]
        private PolicyTier0GatewayRedistributionConfig(
            bool? enabled,

            ImmutableArray<Outputs.PolicyTier0GatewayRedistributionConfigRule> rules)
        {
            Enabled = enabled;
            Rules = rules;
        }
    }
}
