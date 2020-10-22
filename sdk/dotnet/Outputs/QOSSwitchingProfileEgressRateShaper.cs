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
    public sealed class QOSSwitchingProfileEgressRateShaper
    {
        public readonly int? AverageBwMbps;
        public readonly int? BurstSize;
        public readonly bool? Enabled;
        public readonly int? PeakBwMbps;

        [OutputConstructor]
        private QOSSwitchingProfileEgressRateShaper(
            int? averageBwMbps,

            int? burstSize,

            bool? enabled,

            int? peakBwMbps)
        {
            AverageBwMbps = averageBwMbps;
            BurstSize = burstSize;
            Enabled = enabled;
            PeakBwMbps = peakBwMbps;
        }
    }
}
