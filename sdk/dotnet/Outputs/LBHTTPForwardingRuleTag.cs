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
    public sealed class LBHTTPForwardingRuleTag
    {
        public readonly string? Scope;
        public readonly string? Tag;

        [OutputConstructor]
        private LBHTTPForwardingRuleTag(
            string? scope,

            string? tag)
        {
            Scope = scope;
            Tag = tag;
        }
    }
}
