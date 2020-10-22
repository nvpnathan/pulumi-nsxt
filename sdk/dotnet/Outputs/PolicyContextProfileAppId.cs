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
    public sealed class PolicyContextProfileAppId
    {
        public readonly string? Description;
        public readonly bool? IsAlgType;
        public readonly Outputs.PolicyContextProfileAppIdSubAttribute? SubAttribute;
        public readonly ImmutableArray<string> Values;

        [OutputConstructor]
        private PolicyContextProfileAppId(
            string? description,

            bool? isAlgType,

            Outputs.PolicyContextProfileAppIdSubAttribute? subAttribute,

            ImmutableArray<string> values)
        {
            Description = description;
            IsAlgType = isAlgType;
            SubAttribute = subAttribute;
            Values = values;
        }
    }
}
