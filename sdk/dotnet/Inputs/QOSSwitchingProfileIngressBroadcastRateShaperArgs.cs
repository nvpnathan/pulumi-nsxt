// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt.Inputs
{

    public sealed class QOSSwitchingProfileIngressBroadcastRateShaperArgs : Pulumi.ResourceArgs
    {
        [Input("averageBwKbps")]
        public Input<int>? AverageBwKbps { get; set; }

        [Input("burstSize")]
        public Input<int>? BurstSize { get; set; }

        [Input("enabled")]
        public Input<bool>? Enabled { get; set; }

        [Input("peakBwKbps")]
        public Input<int>? PeakBwKbps { get; set; }

        public QOSSwitchingProfileIngressBroadcastRateShaperArgs()
        {
        }
    }
}
