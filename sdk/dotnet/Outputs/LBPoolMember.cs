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
    public sealed class LBPoolMember
    {
        public readonly string? AdminState;
        public readonly bool? BackupMember;
        public readonly string? DisplayName;
        public readonly string IpAddress;
        public readonly int? MaxConcurrentConnections;
        public readonly string? Port;
        public readonly int? Weight;

        [OutputConstructor]
        private LBPoolMember(
            string? adminState,

            bool? backupMember,

            string? displayName,

            string ipAddress,

            int? maxConcurrentConnections,

            string? port,

            int? weight)
        {
            AdminState = adminState;
            BackupMember = backupMember;
            DisplayName = displayName;
            IpAddress = ipAddress;
            MaxConcurrentConnections = maxConcurrentConnections;
            Port = port;
            Weight = weight;
        }
    }
}
