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
    public sealed class PolicyBGPNeighborBfdConfig
    {
        public readonly bool? Enabled;
        public readonly int? Interval;
        public readonly int? Multiple;

        [OutputConstructor]
        private PolicyBGPNeighborBfdConfig(
            bool? enabled,

            int? interval,

            int? multiple)
        {
            Enabled = enabled;
            Interval = interval;
            Multiple = multiple;
        }
    }
}
