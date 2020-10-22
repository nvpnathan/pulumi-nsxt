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
    public sealed class LogicalRouterDownlinkPortServiceBinding
    {
        public readonly bool? IsValid;
        public readonly string? TargetDisplayName;
        public readonly string? TargetId;
        public readonly string? TargetType;

        [OutputConstructor]
        private LogicalRouterDownlinkPortServiceBinding(
            bool? isValid,

            string? targetDisplayName,

            string? targetId,

            string? targetType)
        {
            IsValid = isValid;
            TargetDisplayName = targetDisplayName;
            TargetId = targetId;
            TargetType = targetType;
        }
    }
}
