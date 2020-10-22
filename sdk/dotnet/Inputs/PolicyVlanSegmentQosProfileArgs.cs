// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt.Inputs
{

    public sealed class PolicyVlanSegmentQosProfileArgs : Pulumi.ResourceArgs
    {
        [Input("bindingMapPath")]
        public Input<string>? BindingMapPath { get; set; }

        [Input("qosProfilePath", required: true)]
        public Input<string> QosProfilePath { get; set; } = null!;

        [Input("revision")]
        public Input<int>? Revision { get; set; }

        public PolicyVlanSegmentQosProfileArgs()
        {
        }
    }
}
