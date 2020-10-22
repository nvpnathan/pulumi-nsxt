// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt
{
    /// <summary>
    /// The provider type for the nsxt package. By default, resources use package-wide configuration
    /// settings, however an explicit `Provider` instance may be created and passed during resource
    /// construction to achieve fine-grained programmatic control over provider settings. See the
    /// [documentation](https://www.pulumi.com/docs/reference/programming-model/#providers) for more information.
    /// </summary>
    public partial class Provider : Pulumi.ProviderResource
    {
        /// <summary>
        /// Create a Provider resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public Provider(string name, ProviderArgs? args = null, CustomResourceOptions? options = null)
            : base("nsxt", name, args ?? new ProviderArgs(), MakeResourceOptions(options, ""))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
    }

    public sealed class ProviderArgs : Pulumi.ResourceArgs
    {
        [Input("allowUnverifiedSsl", json: true)]
        public Input<bool>? AllowUnverifiedSsl { get; set; }

        [Input("caFile")]
        public Input<string>? CaFile { get; set; }

        [Input("clientAuthCertFile")]
        public Input<string>? ClientAuthCertFile { get; set; }

        [Input("clientAuthKeyFile")]
        public Input<string>? ClientAuthKeyFile { get; set; }

        /// <summary>
        /// Enforcement Point for NSXT Policy
        /// </summary>
        [Input("enforcementPoint")]
        public Input<string>? EnforcementPoint { get; set; }

        /// <summary>
        /// Is this a policy global manager endpoint
        /// </summary>
        [Input("globalManager", json: true)]
        public Input<bool>? GlobalManager { get; set; }

        /// <summary>
        /// The hostname or IP address of the NSX manager.
        /// </summary>
        [Input("host")]
        public Input<string>? Host { get; set; }

        /// <summary>
        /// Maximum number of HTTP client retries
        /// </summary>
        [Input("maxRetries", json: true)]
        public Input<int>? MaxRetries { get; set; }

        [Input("password")]
        public Input<string>? Password { get; set; }

        [Input("remoteAuth", json: true)]
        public Input<bool>? RemoteAuth { get; set; }

        /// <summary>
        /// Maximum delay in milliseconds between retries of a request
        /// </summary>
        [Input("retryMaxDelay", json: true)]
        public Input<int>? RetryMaxDelay { get; set; }

        /// <summary>
        /// Minimum delay in milliseconds between retries of a request
        /// </summary>
        [Input("retryMinDelay", json: true)]
        public Input<int>? RetryMinDelay { get; set; }

        [Input("retryOnStatusCodes", json: true)]
        private InputList<int>? _retryOnStatusCodes;

        /// <summary>
        /// HTTP replies status codes to retry on
        /// </summary>
        public InputList<int> RetryOnStatusCodes
        {
            get => _retryOnStatusCodes ?? (_retryOnStatusCodes = new InputList<int>());
            set => _retryOnStatusCodes = value;
        }

        /// <summary>
        /// Treat partial success status as success
        /// </summary>
        [Input("toleratePartialSuccess", json: true)]
        public Input<bool>? ToleratePartialSuccess { get; set; }

        [Input("username")]
        public Input<string>? Username { get; set; }

        /// <summary>
        /// URL for VMC authorization service (CSP)
        /// </summary>
        [Input("vmcAuthHost")]
        public Input<string>? VmcAuthHost { get; set; }

        /// <summary>
        /// Long-living API token for VMC authorization
        /// </summary>
        [Input("vmcToken")]
        public Input<string>? VmcToken { get; set; }

        public ProviderArgs()
        {
            AllowUnverifiedSsl = Utilities.GetEnvBoolean("NSXT_ALLOW_UNVERIFIED_SSL");
            CaFile = Utilities.GetEnv("NSXT_CA_FILE");
            ClientAuthCertFile = Utilities.GetEnv("NSXT_CLIENT_AUTH_CERT_FILE");
            ClientAuthKeyFile = Utilities.GetEnv("NSXT_CLIENT_AUTH_KEY_FILE");
            EnforcementPoint = Utilities.GetEnv("NSXT_POLICY_ENFORCEMENT_POINT");
            GlobalManager = Utilities.GetEnvBoolean("NSXT_GLOBAL_MANAGER");
            Host = Utilities.GetEnv("NSXT_MANAGER_HOST");
            MaxRetries = Utilities.GetEnvInt32("NSXT_MAX_RETRIES");
            Password = Utilities.GetEnv("NSXT_PASSWORD");
            RemoteAuth = Utilities.GetEnvBoolean("NSXT_REMOTE_AUTH");
            RetryMaxDelay = Utilities.GetEnvInt32("NSXT_RETRY_MAX_DELAY");
            RetryMinDelay = Utilities.GetEnvInt32("NSXT_RETRY_MIN_DELAY");
            ToleratePartialSuccess = Utilities.GetEnvBoolean("NSXT_TOLERATE_PARTIAL_SUCCESS");
            Username = Utilities.GetEnv("NSXT_USERNAME");
            VmcAuthHost = Utilities.GetEnv("NSXT_VMC_AUTH_HOST");
            VmcToken = Utilities.GetEnv("NSXT_VMC_TOKEN");
        }
    }
}