// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt.Inputs
{

    public sealed class PolicyLBVirtualServerServerSslGetArgs : Pulumi.ResourceArgs
    {
        [Input("caPaths")]
        private InputList<string>? _caPaths;
        public InputList<string> CaPaths
        {
            get => _caPaths ?? (_caPaths = new InputList<string>());
            set => _caPaths = value;
        }

        [Input("certificateChainDepth")]
        public Input<int>? CertificateChainDepth { get; set; }

        [Input("clientCertificatePath")]
        public Input<string>? ClientCertificatePath { get; set; }

        [Input("crlPaths")]
        private InputList<string>? _crlPaths;
        public InputList<string> CrlPaths
        {
            get => _crlPaths ?? (_crlPaths = new InputList<string>());
            set => _crlPaths = value;
        }

        [Input("serverAuth")]
        public Input<string>? ServerAuth { get; set; }

        [Input("sslProfilePath")]
        public Input<string>? SslProfilePath { get; set; }

        public PolicyLBVirtualServerServerSslGetArgs()
        {
        }
    }
}
