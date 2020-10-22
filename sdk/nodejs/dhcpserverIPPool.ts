// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "./types/input";
import * as outputs from "./types/output";
import * as utilities from "./utilities";

export class DHCPServerIPPool extends pulumi.CustomResource {
    /**
     * Get an existing DHCPServerIPPool resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: DHCPServerIPPoolState, opts?: pulumi.CustomResourceOptions): DHCPServerIPPool {
        return new DHCPServerIPPool(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'nsxt:index/dHCPServerIPPool:DHCPServerIPPool';

    /**
     * Returns true if the given object is an instance of DHCPServerIPPool.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is DHCPServerIPPool {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === DHCPServerIPPool.__pulumiType;
    }

    /**
     * Description of this resource
     */
    public readonly description!: pulumi.Output<string | undefined>;
    /**
     * Generic DHCP options
     */
    public readonly dhcpGenericOptions!: pulumi.Output<outputs.DHCPServerIPPoolDhcpGenericOption[] | undefined>;
    /**
     * DHCP classless static routes
     */
    public readonly dhcpOption121s!: pulumi.Output<outputs.DHCPServerIPPoolDhcpOption121[] | undefined>;
    /**
     * The display name of this resource. Defaults to ID if not set
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * Error threshold
     */
    public readonly errorThreshold!: pulumi.Output<number | undefined>;
    /**
     * Gateway ip
     */
    public readonly gatewayIp!: pulumi.Output<string | undefined>;
    /**
     * List of IP Ranges
     */
    public readonly ipRanges!: pulumi.Output<outputs.DHCPServerIPPoolIpRange[] | undefined>;
    /**
     * Lease time, in seconds
     */
    public readonly leaseTime!: pulumi.Output<number | undefined>;
    /**
     * Id of dhcp server this pool is serving
     */
    public readonly logicalDhcpServerId!: pulumi.Output<string>;
    /**
     * The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
     * changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
     * operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
     */
    public /*out*/ readonly revision!: pulumi.Output<number>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    public readonly tags!: pulumi.Output<outputs.DHCPServerIPPoolTag[] | undefined>;
    /**
     * Warning threshold
     */
    public readonly warningThreshold!: pulumi.Output<number | undefined>;

    /**
     * Create a DHCPServerIPPool resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: DHCPServerIPPoolArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: DHCPServerIPPoolArgs | DHCPServerIPPoolState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        if (opts && opts.id) {
            const state = argsOrState as DHCPServerIPPoolState | undefined;
            inputs["description"] = state ? state.description : undefined;
            inputs["dhcpGenericOptions"] = state ? state.dhcpGenericOptions : undefined;
            inputs["dhcpOption121s"] = state ? state.dhcpOption121s : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["errorThreshold"] = state ? state.errorThreshold : undefined;
            inputs["gatewayIp"] = state ? state.gatewayIp : undefined;
            inputs["ipRanges"] = state ? state.ipRanges : undefined;
            inputs["leaseTime"] = state ? state.leaseTime : undefined;
            inputs["logicalDhcpServerId"] = state ? state.logicalDhcpServerId : undefined;
            inputs["revision"] = state ? state.revision : undefined;
            inputs["tags"] = state ? state.tags : undefined;
            inputs["warningThreshold"] = state ? state.warningThreshold : undefined;
        } else {
            const args = argsOrState as DHCPServerIPPoolArgs | undefined;
            if (!args || args.logicalDhcpServerId === undefined) {
                throw new Error("Missing required property 'logicalDhcpServerId'");
            }
            inputs["description"] = args ? args.description : undefined;
            inputs["dhcpGenericOptions"] = args ? args.dhcpGenericOptions : undefined;
            inputs["dhcpOption121s"] = args ? args.dhcpOption121s : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["errorThreshold"] = args ? args.errorThreshold : undefined;
            inputs["gatewayIp"] = args ? args.gatewayIp : undefined;
            inputs["ipRanges"] = args ? args.ipRanges : undefined;
            inputs["leaseTime"] = args ? args.leaseTime : undefined;
            inputs["logicalDhcpServerId"] = args ? args.logicalDhcpServerId : undefined;
            inputs["tags"] = args ? args.tags : undefined;
            inputs["warningThreshold"] = args ? args.warningThreshold : undefined;
            inputs["revision"] = undefined /*out*/;
        }
        if (!opts) {
            opts = {}
        }

        if (!opts.version) {
            opts.version = utilities.getVersion();
        }
        super(DHCPServerIPPool.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering DHCPServerIPPool resources.
 */
export interface DHCPServerIPPoolState {
    /**
     * Description of this resource
     */
    readonly description?: pulumi.Input<string>;
    /**
     * Generic DHCP options
     */
    readonly dhcpGenericOptions?: pulumi.Input<pulumi.Input<inputs.DHCPServerIPPoolDhcpGenericOption>[]>;
    /**
     * DHCP classless static routes
     */
    readonly dhcpOption121s?: pulumi.Input<pulumi.Input<inputs.DHCPServerIPPoolDhcpOption121>[]>;
    /**
     * The display name of this resource. Defaults to ID if not set
     */
    readonly displayName?: pulumi.Input<string>;
    /**
     * Error threshold
     */
    readonly errorThreshold?: pulumi.Input<number>;
    /**
     * Gateway ip
     */
    readonly gatewayIp?: pulumi.Input<string>;
    /**
     * List of IP Ranges
     */
    readonly ipRanges?: pulumi.Input<pulumi.Input<inputs.DHCPServerIPPoolIpRange>[]>;
    /**
     * Lease time, in seconds
     */
    readonly leaseTime?: pulumi.Input<number>;
    /**
     * Id of dhcp server this pool is serving
     */
    readonly logicalDhcpServerId?: pulumi.Input<string>;
    /**
     * The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
     * changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
     * operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
     */
    readonly revision?: pulumi.Input<number>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.DHCPServerIPPoolTag>[]>;
    /**
     * Warning threshold
     */
    readonly warningThreshold?: pulumi.Input<number>;
}

/**
 * The set of arguments for constructing a DHCPServerIPPool resource.
 */
export interface DHCPServerIPPoolArgs {
    /**
     * Description of this resource
     */
    readonly description?: pulumi.Input<string>;
    /**
     * Generic DHCP options
     */
    readonly dhcpGenericOptions?: pulumi.Input<pulumi.Input<inputs.DHCPServerIPPoolDhcpGenericOption>[]>;
    /**
     * DHCP classless static routes
     */
    readonly dhcpOption121s?: pulumi.Input<pulumi.Input<inputs.DHCPServerIPPoolDhcpOption121>[]>;
    /**
     * The display name of this resource. Defaults to ID if not set
     */
    readonly displayName?: pulumi.Input<string>;
    /**
     * Error threshold
     */
    readonly errorThreshold?: pulumi.Input<number>;
    /**
     * Gateway ip
     */
    readonly gatewayIp?: pulumi.Input<string>;
    /**
     * List of IP Ranges
     */
    readonly ipRanges?: pulumi.Input<pulumi.Input<inputs.DHCPServerIPPoolIpRange>[]>;
    /**
     * Lease time, in seconds
     */
    readonly leaseTime?: pulumi.Input<number>;
    /**
     * Id of dhcp server this pool is serving
     */
    readonly logicalDhcpServerId: pulumi.Input<string>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.DHCPServerIPPoolTag>[]>;
    /**
     * Warning threshold
     */
    readonly warningThreshold?: pulumi.Input<number>;
}
