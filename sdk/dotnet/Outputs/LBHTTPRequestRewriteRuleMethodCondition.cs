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
    public sealed class LBHTTPRequestRewriteRuleMethodCondition
    {
        public readonly bool? Inverse;
        public readonly string Method;

        [OutputConstructor]
        private LBHTTPRequestRewriteRuleMethodCondition(
            bool? inverse,

            string method)
        {
            Inverse = inverse;
            Method = method;
        }
    }
}