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
    public sealed class PolicyVlanSegmentDiscoveryProfile
    {
        public readonly string? BindingMapPath;
        public readonly string? IpDiscoveryProfilePath;
        public readonly string? MacDiscoveryProfilePath;
        public readonly int? Revision;

        [OutputConstructor]
        private PolicyVlanSegmentDiscoveryProfile(
            string? bindingMapPath,

            string? ipDiscoveryProfilePath,

            string? macDiscoveryProfilePath,

            int? revision)
        {
            BindingMapPath = bindingMapPath;
            IpDiscoveryProfilePath = ipDiscoveryProfilePath;
            MacDiscoveryProfilePath = macDiscoveryProfilePath;
            Revision = revision;
        }
    }
}
