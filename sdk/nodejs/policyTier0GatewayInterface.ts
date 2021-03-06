// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "./types/input";
import * as outputs from "./types/output";
import * as utilities from "./utilities";

export class PolicyTier0GatewayInterface extends pulumi.CustomResource {
    /**
     * Get an existing PolicyTier0GatewayInterface resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: PolicyTier0GatewayInterfaceState, opts?: pulumi.CustomResourceOptions): PolicyTier0GatewayInterface {
        return new PolicyTier0GatewayInterface(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'nsxt:index/policyTier0GatewayInterface:PolicyTier0GatewayInterface';

    /**
     * Returns true if the given object is an instance of PolicyTier0GatewayInterface.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is PolicyTier0GatewayInterface {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === PolicyTier0GatewayInterface.__pulumiType;
    }

    /**
     * Vlan ID
     */
    public readonly accessVlanId!: pulumi.Output<number | undefined>;
    /**
     * Description for this resource
     */
    public readonly description!: pulumi.Output<string | undefined>;
    /**
     * Display name for this resource
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * Policy path for edge node
     */
    public readonly edgeNodePath!: pulumi.Output<string | undefined>;
    /**
     * Enable Protocol Independent Multicast on Interface
     */
    public readonly enablePim!: pulumi.Output<boolean | undefined>;
    /**
     * Policy path for Tier0 gateway
     */
    public readonly gatewayPath!: pulumi.Output<string>;
    /**
     * Ip addresses
     */
    public /*out*/ readonly ipAddresses!: pulumi.Output<string[]>;
    /**
     * The path of an IPv6 NDRA profile
     */
    public readonly ipv6NdraProfilePath!: pulumi.Output<string>;
    /**
     * Id of associated Gateway Locale Service on NSX
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
    public readonly segmentPath!: pulumi.Output<string | undefined>;
    /**
     * Path of the site the Tier0 edge cluster belongs to
     */
    public readonly sitePath!: pulumi.Output<string | undefined>;
    /**
     * List of IP addresses and network prefixes for this interface
     */
    public readonly subnets!: pulumi.Output<string[]>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    public readonly tags!: pulumi.Output<outputs.PolicyTier0GatewayInterfaceTag[] | undefined>;
    /**
     * Interface Type
     */
    public readonly type!: pulumi.Output<string | undefined>;
    /**
     * Unicast Reverse Path Forwarding mode
     */
    public readonly urpfMode!: pulumi.Output<string | undefined>;

    /**
     * Create a PolicyTier0GatewayInterface resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: PolicyTier0GatewayInterfaceArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: PolicyTier0GatewayInterfaceArgs | PolicyTier0GatewayInterfaceState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        if (opts && opts.id) {
            const state = argsOrState as PolicyTier0GatewayInterfaceState | undefined;
            inputs["accessVlanId"] = state ? state.accessVlanId : undefined;
            inputs["description"] = state ? state.description : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["edgeNodePath"] = state ? state.edgeNodePath : undefined;
            inputs["enablePim"] = state ? state.enablePim : undefined;
            inputs["gatewayPath"] = state ? state.gatewayPath : undefined;
            inputs["ipAddresses"] = state ? state.ipAddresses : undefined;
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
            inputs["type"] = state ? state.type : undefined;
            inputs["urpfMode"] = state ? state.urpfMode : undefined;
        } else {
            const args = argsOrState as PolicyTier0GatewayInterfaceArgs | undefined;
            if (!args || args.displayName === undefined) {
                throw new Error("Missing required property 'displayName'");
            }
            if (!args || args.gatewayPath === undefined) {
                throw new Error("Missing required property 'gatewayPath'");
            }
            if (!args || args.subnets === undefined) {
                throw new Error("Missing required property 'subnets'");
            }
            inputs["accessVlanId"] = args ? args.accessVlanId : undefined;
            inputs["description"] = args ? args.description : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["edgeNodePath"] = args ? args.edgeNodePath : undefined;
            inputs["enablePim"] = args ? args.enablePim : undefined;
            inputs["gatewayPath"] = args ? args.gatewayPath : undefined;
            inputs["ipv6NdraProfilePath"] = args ? args.ipv6NdraProfilePath : undefined;
            inputs["mtu"] = args ? args.mtu : undefined;
            inputs["nsxId"] = args ? args.nsxId : undefined;
            inputs["segmentPath"] = args ? args.segmentPath : undefined;
            inputs["sitePath"] = args ? args.sitePath : undefined;
            inputs["subnets"] = args ? args.subnets : undefined;
            inputs["tags"] = args ? args.tags : undefined;
            inputs["type"] = args ? args.type : undefined;
            inputs["urpfMode"] = args ? args.urpfMode : undefined;
            inputs["ipAddresses"] = undefined /*out*/;
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
        super(PolicyTier0GatewayInterface.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering PolicyTier0GatewayInterface resources.
 */
export interface PolicyTier0GatewayInterfaceState {
    /**
     * Vlan ID
     */
    readonly accessVlanId?: pulumi.Input<number>;
    /**
     * Description for this resource
     */
    readonly description?: pulumi.Input<string>;
    /**
     * Display name for this resource
     */
    readonly displayName?: pulumi.Input<string>;
    /**
     * Policy path for edge node
     */
    readonly edgeNodePath?: pulumi.Input<string>;
    /**
     * Enable Protocol Independent Multicast on Interface
     */
    readonly enablePim?: pulumi.Input<boolean>;
    /**
     * Policy path for Tier0 gateway
     */
    readonly gatewayPath?: pulumi.Input<string>;
    /**
     * Ip addresses
     */
    readonly ipAddresses?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The path of an IPv6 NDRA profile
     */
    readonly ipv6NdraProfilePath?: pulumi.Input<string>;
    /**
     * Id of associated Gateway Locale Service on NSX
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
     * Path of the site the Tier0 edge cluster belongs to
     */
    readonly sitePath?: pulumi.Input<string>;
    /**
     * List of IP addresses and network prefixes for this interface
     */
    readonly subnets?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.PolicyTier0GatewayInterfaceTag>[]>;
    /**
     * Interface Type
     */
    readonly type?: pulumi.Input<string>;
    /**
     * Unicast Reverse Path Forwarding mode
     */
    readonly urpfMode?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a PolicyTier0GatewayInterface resource.
 */
export interface PolicyTier0GatewayInterfaceArgs {
    /**
     * Vlan ID
     */
    readonly accessVlanId?: pulumi.Input<number>;
    /**
     * Description for this resource
     */
    readonly description?: pulumi.Input<string>;
    /**
     * Display name for this resource
     */
    readonly displayName: pulumi.Input<string>;
    /**
     * Policy path for edge node
     */
    readonly edgeNodePath?: pulumi.Input<string>;
    /**
     * Enable Protocol Independent Multicast on Interface
     */
    readonly enablePim?: pulumi.Input<boolean>;
    /**
     * Policy path for Tier0 gateway
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
    readonly segmentPath?: pulumi.Input<string>;
    /**
     * Path of the site the Tier0 edge cluster belongs to
     */
    readonly sitePath?: pulumi.Input<string>;
    /**
     * List of IP addresses and network prefixes for this interface
     */
    readonly subnets: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.PolicyTier0GatewayInterfaceTag>[]>;
    /**
     * Interface Type
     */
    readonly type?: pulumi.Input<string>;
    /**
     * Unicast Reverse Path Forwarding mode
     */
    readonly urpfMode?: pulumi.Input<string>;
}
