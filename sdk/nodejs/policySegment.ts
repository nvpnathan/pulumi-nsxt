// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "./types/input";
import * as outputs from "./types/output";
import * as utilities from "./utilities";

export class PolicySegment extends pulumi.CustomResource {
    /**
     * Get an existing PolicySegment resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: PolicySegmentState, opts?: pulumi.CustomResourceOptions): PolicySegment {
        return new PolicySegment(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'nsxt:index/policySegment:PolicySegment';

    /**
     * Returns true if the given object is an instance of PolicySegment.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is PolicySegment {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === PolicySegment.__pulumiType;
    }

    /**
     * Advanced segment configuration
     */
    public readonly advancedConfig!: pulumi.Output<outputs.PolicySegmentAdvancedConfig | undefined>;
    /**
     * Policy path to the connecting Tier-0 or Tier-1
     */
    public readonly connectivityPath!: pulumi.Output<string | undefined>;
    /**
     * Description for this resource
     */
    public readonly description!: pulumi.Output<string | undefined>;
    /**
     * Policy path to DHCP server or relay configuration to use for subnets configured on this segment
     */
    public readonly dhcpConfigPath!: pulumi.Output<string | undefined>;
    /**
     * IP and MAC discovery profiles for this segment
     */
    public readonly discoveryProfile!: pulumi.Output<outputs.PolicySegmentDiscoveryProfile | undefined>;
    /**
     * Display name for this resource
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * DNS domain names
     */
    public readonly domainName!: pulumi.Output<string | undefined>;
    /**
     * Configuration for extending Segment through L2 VPN
     */
    public readonly l2Extension!: pulumi.Output<outputs.PolicySegmentL2Extension | undefined>;
    /**
     * NSX ID for this resource
     */
    public readonly nsxId!: pulumi.Output<string>;
    /**
     * Overlay connectivity ID for this Segment
     */
    public readonly overlayId!: pulumi.Output<number>;
    /**
     * Policy path for this resource
     */
    public /*out*/ readonly path!: pulumi.Output<string>;
    /**
     * QoS profiles for this segment
     */
    public readonly qosProfile!: pulumi.Output<outputs.PolicySegmentQosProfile | undefined>;
    /**
     * The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
     * changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
     * operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
     */
    public /*out*/ readonly revision!: pulumi.Output<number>;
    /**
     * Security profiles for this segment
     */
    public readonly securityProfile!: pulumi.Output<outputs.PolicySegmentSecurityProfile | undefined>;
    /**
     * Subnet configuration with at most 1 IPv4 CIDR and multiple IPv6 CIDRs
     */
    public readonly subnets!: pulumi.Output<outputs.PolicySegmentSubnet[] | undefined>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    public readonly tags!: pulumi.Output<outputs.PolicySegmentTag[] | undefined>;
    /**
     * Policy path to the transport zone
     */
    public readonly transportZonePath!: pulumi.Output<string>;
    /**
     * VLAN IDs for VLAN backed Segment
     */
    public readonly vlanIds!: pulumi.Output<string[] | undefined>;

    /**
     * Create a PolicySegment resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: PolicySegmentArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: PolicySegmentArgs | PolicySegmentState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        if (opts && opts.id) {
            const state = argsOrState as PolicySegmentState | undefined;
            inputs["advancedConfig"] = state ? state.advancedConfig : undefined;
            inputs["connectivityPath"] = state ? state.connectivityPath : undefined;
            inputs["description"] = state ? state.description : undefined;
            inputs["dhcpConfigPath"] = state ? state.dhcpConfigPath : undefined;
            inputs["discoveryProfile"] = state ? state.discoveryProfile : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["domainName"] = state ? state.domainName : undefined;
            inputs["l2Extension"] = state ? state.l2Extension : undefined;
            inputs["nsxId"] = state ? state.nsxId : undefined;
            inputs["overlayId"] = state ? state.overlayId : undefined;
            inputs["path"] = state ? state.path : undefined;
            inputs["qosProfile"] = state ? state.qosProfile : undefined;
            inputs["revision"] = state ? state.revision : undefined;
            inputs["securityProfile"] = state ? state.securityProfile : undefined;
            inputs["subnets"] = state ? state.subnets : undefined;
            inputs["tags"] = state ? state.tags : undefined;
            inputs["transportZonePath"] = state ? state.transportZonePath : undefined;
            inputs["vlanIds"] = state ? state.vlanIds : undefined;
        } else {
            const args = argsOrState as PolicySegmentArgs | undefined;
            if (!args || args.displayName === undefined) {
                throw new Error("Missing required property 'displayName'");
            }
            if (!args || args.transportZonePath === undefined) {
                throw new Error("Missing required property 'transportZonePath'");
            }
            inputs["advancedConfig"] = args ? args.advancedConfig : undefined;
            inputs["connectivityPath"] = args ? args.connectivityPath : undefined;
            inputs["description"] = args ? args.description : undefined;
            inputs["dhcpConfigPath"] = args ? args.dhcpConfigPath : undefined;
            inputs["discoveryProfile"] = args ? args.discoveryProfile : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["domainName"] = args ? args.domainName : undefined;
            inputs["l2Extension"] = args ? args.l2Extension : undefined;
            inputs["nsxId"] = args ? args.nsxId : undefined;
            inputs["overlayId"] = args ? args.overlayId : undefined;
            inputs["qosProfile"] = args ? args.qosProfile : undefined;
            inputs["securityProfile"] = args ? args.securityProfile : undefined;
            inputs["subnets"] = args ? args.subnets : undefined;
            inputs["tags"] = args ? args.tags : undefined;
            inputs["transportZonePath"] = args ? args.transportZonePath : undefined;
            inputs["vlanIds"] = args ? args.vlanIds : undefined;
            inputs["path"] = undefined /*out*/;
            inputs["revision"] = undefined /*out*/;
        }
        if (!opts) {
            opts = {}
        }

        if (!opts.version) {
            opts.version = utilities.getVersion();
        }
        super(PolicySegment.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering PolicySegment resources.
 */
export interface PolicySegmentState {
    /**
     * Advanced segment configuration
     */
    readonly advancedConfig?: pulumi.Input<inputs.PolicySegmentAdvancedConfig>;
    /**
     * Policy path to the connecting Tier-0 or Tier-1
     */
    readonly connectivityPath?: pulumi.Input<string>;
    /**
     * Description for this resource
     */
    readonly description?: pulumi.Input<string>;
    /**
     * Policy path to DHCP server or relay configuration to use for subnets configured on this segment
     */
    readonly dhcpConfigPath?: pulumi.Input<string>;
    /**
     * IP and MAC discovery profiles for this segment
     */
    readonly discoveryProfile?: pulumi.Input<inputs.PolicySegmentDiscoveryProfile>;
    /**
     * Display name for this resource
     */
    readonly displayName?: pulumi.Input<string>;
    /**
     * DNS domain names
     */
    readonly domainName?: pulumi.Input<string>;
    /**
     * Configuration for extending Segment through L2 VPN
     */
    readonly l2Extension?: pulumi.Input<inputs.PolicySegmentL2Extension>;
    /**
     * NSX ID for this resource
     */
    readonly nsxId?: pulumi.Input<string>;
    /**
     * Overlay connectivity ID for this Segment
     */
    readonly overlayId?: pulumi.Input<number>;
    /**
     * Policy path for this resource
     */
    readonly path?: pulumi.Input<string>;
    /**
     * QoS profiles for this segment
     */
    readonly qosProfile?: pulumi.Input<inputs.PolicySegmentQosProfile>;
    /**
     * The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
     * changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
     * operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
     */
    readonly revision?: pulumi.Input<number>;
    /**
     * Security profiles for this segment
     */
    readonly securityProfile?: pulumi.Input<inputs.PolicySegmentSecurityProfile>;
    /**
     * Subnet configuration with at most 1 IPv4 CIDR and multiple IPv6 CIDRs
     */
    readonly subnets?: pulumi.Input<pulumi.Input<inputs.PolicySegmentSubnet>[]>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.PolicySegmentTag>[]>;
    /**
     * Policy path to the transport zone
     */
    readonly transportZonePath?: pulumi.Input<string>;
    /**
     * VLAN IDs for VLAN backed Segment
     */
    readonly vlanIds?: pulumi.Input<pulumi.Input<string>[]>;
}

/**
 * The set of arguments for constructing a PolicySegment resource.
 */
export interface PolicySegmentArgs {
    /**
     * Advanced segment configuration
     */
    readonly advancedConfig?: pulumi.Input<inputs.PolicySegmentAdvancedConfig>;
    /**
     * Policy path to the connecting Tier-0 or Tier-1
     */
    readonly connectivityPath?: pulumi.Input<string>;
    /**
     * Description for this resource
     */
    readonly description?: pulumi.Input<string>;
    /**
     * Policy path to DHCP server or relay configuration to use for subnets configured on this segment
     */
    readonly dhcpConfigPath?: pulumi.Input<string>;
    /**
     * IP and MAC discovery profiles for this segment
     */
    readonly discoveryProfile?: pulumi.Input<inputs.PolicySegmentDiscoveryProfile>;
    /**
     * Display name for this resource
     */
    readonly displayName: pulumi.Input<string>;
    /**
     * DNS domain names
     */
    readonly domainName?: pulumi.Input<string>;
    /**
     * Configuration for extending Segment through L2 VPN
     */
    readonly l2Extension?: pulumi.Input<inputs.PolicySegmentL2Extension>;
    /**
     * NSX ID for this resource
     */
    readonly nsxId?: pulumi.Input<string>;
    /**
     * Overlay connectivity ID for this Segment
     */
    readonly overlayId?: pulumi.Input<number>;
    /**
     * QoS profiles for this segment
     */
    readonly qosProfile?: pulumi.Input<inputs.PolicySegmentQosProfile>;
    /**
     * Security profiles for this segment
     */
    readonly securityProfile?: pulumi.Input<inputs.PolicySegmentSecurityProfile>;
    /**
     * Subnet configuration with at most 1 IPv4 CIDR and multiple IPv6 CIDRs
     */
    readonly subnets?: pulumi.Input<pulumi.Input<inputs.PolicySegmentSubnet>[]>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.PolicySegmentTag>[]>;
    /**
     * Policy path to the transport zone
     */
    readonly transportZonePath: pulumi.Input<string>;
    /**
     * VLAN IDs for VLAN backed Segment
     */
    readonly vlanIds?: pulumi.Input<pulumi.Input<string>[]>;
}
