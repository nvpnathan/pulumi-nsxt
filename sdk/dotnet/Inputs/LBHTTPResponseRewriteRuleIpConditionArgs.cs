// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt.Inputs
{

    public sealed class LBHTTPResponseRewriteRuleIpConditionArgs : Pulumi.ResourceArgs
    {
        [Input("inverse")]
        public Input<bool>? Inverse { get; set; }

        [Input("sourceAddress", required: true)]
        public Input<string> SourceAddress { get; set; } = null!;

        public LBHTTPResponseRewriteRuleIpConditionArgs()
        {
        }
    }
}
