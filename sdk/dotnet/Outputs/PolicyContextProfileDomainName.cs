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
    public sealed class PolicyContextProfileDomainName
    {
        public readonly string? Description;
        public readonly ImmutableArray<string> Values;

        [OutputConstructor]
        private PolicyContextProfileDomainName(
            string? description,

            ImmutableArray<string> values)
        {
            Description = description;
            Values = values;
        }
    }
}