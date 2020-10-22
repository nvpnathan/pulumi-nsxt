// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "./types/input";
import * as outputs from "./types/output";
import * as utilities from "./utilities";

export class PolicyTier1GatewayInterface extends pulumi.CustomResource {
    /**
     * Get an existing PolicyTier1GatewayInterface resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: PolicyTier1GatewayInterfaceState, opts?: pulumi.CustomResourceOptions): PolicyTier1GatewayInterface {
        return new PolicyTier1GatewayInterface(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'nsxt:index/policyTier1GatewayInterface:PolicyTier1GatewayInterface';

    /**
     * Returns true if the given object is an instance of PolicyTier1GatewayInterface.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is PolicyTier1GatewayInterface {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === PolicyTier1GatewayInterface.__pulumiType;
    }

    /**
     * Description for this resource
     */
    public readonly description!: pulumi.Output<string | undefined>;
    /**
     * Display name for this resource
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * Policy path for tier1 gateway
     */
    public readonly gatewayPath!: pulumi.Output<string>;
    /**
     * The path of an IPv6 NDRA profile
     */
    public readonly ipv6NdraProfilePath!: pulumi.Output<string>;
    /**
     * Locale Service ID for this interface
     */
    public /*out*/ readonly localeServiceId!: pulumi.Output<string>;
    /**
     * Maximum transmission unit specifies the size of the largest packet that a network protocol can transmit
     */
    public readonly mtu!: pulumi.Output<number | undefined>;
    /**
     * NSX ID for this resource
     */
    public readonly nsxId!: pulumi.Output<string>;
    /**
     * Policy path for this resource
     */
    public /*out*/ readonly path!: pulumi.Output<string>;
    /**
     * The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
     * changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
     * operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
     */
    public /*out*/ readonly revision!: pulumi.Output<number>;
    /**
     * Policy path for connected segment
     */
    public readonly segmentPath!: pulumi.Output<string>;
    /**
     * Path of the site the Tier1 edge cluster belongs to
     */
    public readonly sitePath!: pulumi.Output<string | undefined>;
    /**
     * List of IP addresses and network prefixes for this interface
     */
    public readonly subnets!: pulumi.Output<string[]>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    public readonly tags!: pulumi.Output<outputs.PolicyTier1GatewayInterfaceTag[] | undefined>;
    /**
     * Unicast Reverse Path Forwarding mode
     */
    public readonly urpfMode!: pulumi.Output<string | undefined>;

    /**
     * Create a PolicyTier1GatewayInterface resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: PolicyTier1GatewayInterfaceArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: PolicyTier1GatewayInterfaceArgs | PolicyTier1GatewayInterfaceState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        if (opts && opts.id) {
            const state = argsOrState as PolicyTier1GatewayInterfaceState | undefined;
            inputs["description"] = state ? state.description : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["gatewayPath"] = state ? state.gatewayPath : undefined;
            inputs["ipv6NdraProfilePath"] = state ? state.ipv6NdraProfilePath : undefined;
            inputs["localeServiceId"] = state ? state.localeServiceId : undefined;
            inputs["mtu"] = state ? state.mtu : undefined;
            inputs["nsxId"] = state ? state.nsxId : undefined;
            inputs["path"] = state ? state.path : undefined;
            inputs["revision"] = state ? state.revision : undefined;
            inputs["segmentPath"] = state ? state.segmentPath : undefined;
            inputs["sitePath"] = state ? state.sitePath : undefined;
            inputs["subnets"] = state ? state.subnets : undefined;
            inputs["tags"] = state ? state.tags : undefined;
            inputs["urpfMode"] = state ? state.urpfMode : undefined;
        } else {
            const args = argsOrState as PolicyTier1GatewayInterfaceArgs | undefined;
            if (!args || args.displayName === undefined) {
                throw new Error("Missing required property 'displayName'");
            }
            if (!args || args.gatewayPath === undefined) {
                throw new Error("Missing required property 'gatewayPath'");
            }
            if (!args || args.segmentPath === undefined) {
                throw new Error("Missing required property 'segmentPath'");
            }
            if (!args || args.subnets === undefined) {
                throw new Error("Missing required property 'subnets'");
            }
            inputs["description"] = args ? args.description : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["gatewayPath"] = args ? args.gatewayPath : undefined;
            inputs["ipv6NdraProfilePath"] = args ? args.ipv6NdraProfilePath : undefined;
            inputs["mtu"] = args ? args.mtu : undefined;
            inputs["nsxId"] = args ? args.nsxId : undefined;
            inputs["segmentPath"] = args ? args.segmentPath : undefined;
            inputs["sitePath"] = args ? args.sitePath : undefined;
            inputs["subnets"] = args ? args.subnets : undefined;
            inputs["tags"] = args ? args.tags : undefined;
            inputs["urpfMode"] = args ? args.urpfMode : undefined;
            inputs["localeServiceId"] = undefined /*out*/;
            inputs["path"] = undefined /*out*/;
            inputs["revision"] = undefined /*out*/;
        }
        if (!opts) {
            opts = {}
        }

        if (!opts.version) {
            opts.version = utilities.getVersion();
        }
        super(PolicyTier1GatewayInterface.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering PolicyTier1GatewayInterface resources.
 */
export interface PolicyTier1GatewayInterfaceState {
    /**
     * Description for this resource
     */
    readonly description?: pulumi.Input<string>;
    /**
     * Display name for this resource
     */
    readonly displayName?: pulumi.Input<string>;
    /**
     * Policy path for tier1 gateway
     */
    readonly gatewayPath?: pulumi.Input<string>;
    /**
     * The path of an IPv6 NDRA profile
     */
    readonly ipv6NdraProfilePath?: pulumi.Input<string>;
    /**
     * Locale Service ID for this interface
     */
    readonly localeServiceId?: pulumi.Input<string>;
    /**
     * Maximum transmission unit specifies the size of the largest packet that a network protocol can transmit
     */
    readonly mtu?: pulumi.Input<number>;
    /**
     * NSX ID for this resource
     */
    readonly nsxId?: pulumi.Input<string>;
    /**
     * Policy path for this resource
     */
    readonly path?: pulumi.Input<string>;
    /**
     * The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
     * changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
     * operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
     */
    readonly revision?: pulumi.Input<number>;
    /**
     * Policy path for connected segment
     */
    readonly segmentPath?: pulumi.Input<string>;
    /**
     * Path of the site the Tier1 edge cluster belongs to
     */
    readonly sitePath?: pulumi.Input<string>;
    /**
     * List of IP addresses and network prefixes for this interface
     */
    readonly subnets?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.PolicyTier1GatewayInterfaceTag>[]>;
    /**
     * Unicast Reverse Path Forwarding mode
     */
    readonly urpfMode?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a PolicyTier1GatewayInterface resource.
 */
export interface PolicyTier1GatewayInterfaceArgs {
    /**
     * Description for this resource
     */
    readonly description?: pulumi.Input<string>;
    /**
     * Display name for this resource
     */
    readonly displayName: pulumi.Input<string>;
    /**
     * Policy path for tier1 gateway
     */
    readonly gatewayPath: pulumi.Input<string>;
    /**
     * The path of an IPv6 NDRA profile
     */
    readonly ipv6NdraProfilePath?: pulumi.Input<string>;
    /**
     * Maximum transmission unit specifies the size of the largest packet that a network protocol can transmit
     */
    readonly mtu?: pulumi.Input<number>;
    /**
     * NSX ID for this resource
     */
    readonly nsxId?: pulumi.Input<string>;
    /**
     * Policy path for connected segment
     */
    readonly segmentPath: pulumi.Input<string>;
    /**
     * Path of the site the Tier1 edge cluster belongs to
     */
    readonly sitePath?: pulumi.Input<string>;
    /**
     * List of IP addresses and network prefixes for this interface
     */
    readonly subnets: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.PolicyTier1GatewayInterfaceTag>[]>;
    /**
     * Unicast Reverse Path Forwarding mode
     */
    readonly urpfMode?: pulumi.Input<string>;
}