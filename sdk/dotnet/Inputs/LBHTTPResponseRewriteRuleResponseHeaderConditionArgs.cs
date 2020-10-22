// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt.Inputs
{

    public sealed class LBHTTPResponseRewriteRuleResponseHeaderConditionArgs : Pulumi.ResourceArgs
    {
        [Input("caseSensitive")]
        public Input<bool>? CaseSensitive { get; set; }

        [Input("inverse")]
        public Input<bool>? Inverse { get; set; }

        [Input("matchType", required: true)]
        public Input<string> MatchType { get; set; } = null!;

        [Input("name", required: true)]
        public Input<string> Name { get; set; } = null!;

        [Input("value", required: true)]
        public Input<string> Value { get; set; } = null!;

        public LBHTTPResponseRewriteRuleResponseHeaderConditionArgs()
        {
        }
    }
}
