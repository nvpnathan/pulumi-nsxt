// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt.Inputs
{

    public sealed class LBHTTPResponseRewriteRuleTcpConditionArgs : Pulumi.ResourceArgs
    {
        [Input("inverse")]
        public Input<bool>? Inverse { get; set; }

        [Input("sourcePort", required: true)]
        public Input<string> SourcePort { get; set; } = null!;

        public LBHTTPResponseRewriteRuleTcpConditionArgs()
        {
        }
    }
}
