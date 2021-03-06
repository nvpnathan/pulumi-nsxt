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
    public sealed class PolicyGroupExtendedCriteriaIdentityGroup
    {
        public readonly string? DistinguishedName;
        public readonly string? DomainBaseDistinguishedName;
        public readonly string? Sid;

        [OutputConstructor]
        private PolicyGroupExtendedCriteriaIdentityGroup(
            string? distinguishedName,

            string? domainBaseDistinguishedName,

            string? sid)
        {
            DistinguishedName = distinguishedName;
            DomainBaseDistinguishedName = domainBaseDistinguishedName;
            Sid = sid;
        }
    }
}
