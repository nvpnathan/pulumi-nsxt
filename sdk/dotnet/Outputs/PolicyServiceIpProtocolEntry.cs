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
    public sealed class PolicyServiceIpProtocolEntry
    {
        public readonly string? Description;
        public readonly string? DisplayName;
        public readonly int Protocol;

        [OutputConstructor]
        private PolicyServiceIpProtocolEntry(
            string? description,

            string? displayName,

            int protocol)
        {
            Description = description;
            DisplayName = displayName;
            Protocol = protocol;
        }
    }
}
