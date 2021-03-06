// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt.Inputs
{

    public sealed class LBHTTPVirtualServerClientSslArgs : Pulumi.ResourceArgs
    {
        [Input("caIds")]
        private InputList<string>? _caIds;
        public InputList<string> CaIds
        {
            get => _caIds ?? (_caIds = new InputList<string>());
            set => _caIds = value;
        }

        [Input("certificateChainDepth")]
        public Input<int>? CertificateChainDepth { get; set; }

        [Input("clientAuth")]
        public Input<bool>? ClientAuth { get; set; }

        [Input("clientSslProfileId", required: true)]
        public Input<string> ClientSslProfileId { get; set; } = null!;

        [Input("crlIds")]
        private InputList<string>? _crlIds;
        public InputList<string> CrlIds
        {
            get => _crlIds ?? (_crlIds = new InputList<string>());
            set => _crlIds = value;
        }

        [Input("defaultCertificateId", required: true)]
        public Input<string> DefaultCertificateId { get; set; } = null!;

        [Input("sniCertificateIds")]
        private InputList<string>? _sniCertificateIds;
        public InputList<string> SniCertificateIds
        {
            get => _sniCertificateIds ?? (_sniCertificateIds = new InputList<string>());
            set => _sniCertificateIds = value;
        }

        public LBHTTPVirtualServerClientSslArgs()
        {
        }
    }
}
