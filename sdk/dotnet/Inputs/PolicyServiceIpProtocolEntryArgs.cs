// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt.Inputs
{

    public sealed class PolicyServiceIpProtocolEntryArgs : Pulumi.ResourceArgs
    {
        [Input("description")]
        public Input<string>? Description { get; set; }

        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("protocol", required: true)]
        public Input<int> Protocol { get; set; } = null!;

        public PolicyServiceIpProtocolEntryArgs()
        {
        }
    }
}
