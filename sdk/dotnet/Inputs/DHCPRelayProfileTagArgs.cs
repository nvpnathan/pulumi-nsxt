// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt.Inputs
{

    public sealed class DHCPRelayProfileTagArgs : Pulumi.ResourceArgs
    {
        [Input("scope")]
        public Input<string>? Scope { get; set; }

        [Input("tag")]
        public Input<string>? Tag { get; set; }

        public DHCPRelayProfileTagArgs()
        {
        }
    }
}
