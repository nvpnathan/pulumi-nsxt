// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "./types/input";
import * as outputs from "./types/output";
import * as utilities from "./utilities";

export class LBPool extends pulumi.CustomResource {
    /**
     * Get an existing LBPool resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: LBPoolState, opts?: pulumi.CustomResourceOptions): LBPool {
        return new LBPool(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'nsxt:index/lBPool:LBPool';

    /**
     * Returns true if the given object is an instance of LBPool.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is LBPool {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === LBPool.__pulumiType;
    }

    /**
     * Active health monitor Id. If one is not set, the active healthchecks will be disabled
     */
    public readonly activeMonitorId!: pulumi.Output<string | undefined>;
    /**
     * Load balancing algorithm controls how the incoming connections are distributed among the members
     */
    public readonly algorithm!: pulumi.Output<string | undefined>;
    /**
     * Description of this resource
     */
    public readonly description!: pulumi.Output<string | undefined>;
    /**
     * The display name of this resource. Defaults to ID if not set
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * Dynamic pool members for the loadbalancing pool. When member group is defined, members setting should not be specified
     */
    public readonly memberGroup!: pulumi.Output<outputs.LBPoolMemberGroup | undefined>;
    /**
     * List of server pool members. Each pool member is identified, typically, by an IP address and a port
     */
    public readonly members!: pulumi.Output<outputs.LBPoolMember[] | undefined>;
    /**
     * The minimum number of members for the pool to be considered active
     */
    public readonly minActiveMembers!: pulumi.Output<number | undefined>;
    /**
     * Passive health monitor Id. If one is not set, the passive healthchecks will be disabled
     */
    public readonly passiveMonitorId!: pulumi.Output<string | undefined>;
    /**
     * The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
     * changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
     * operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
     */
    public /*out*/ readonly revision!: pulumi.Output<number>;
    /**
     * SNAT translation configuration
     */
    public readonly snatTranslation!: pulumi.Output<outputs.LBPoolSnatTranslation>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    public readonly tags!: pulumi.Output<outputs.LBPoolTag[] | undefined>;
    /**
     * TCP multiplexing allows the same TCP connection between load balancer and the backend server to be used for sending
     * multiple client requests from different client TCP connections
     */
    public readonly tcpMultiplexingEnabled!: pulumi.Output<boolean | undefined>;
    /**
     * The maximum number of TCP connections per pool that are idly kept alive for sending future client requests
     */
    public readonly tcpMultiplexingNumber!: pulumi.Output<number | undefined>;

    /**
     * Create a LBPool resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args?: LBPoolArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: LBPoolArgs | LBPoolState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        if (opts && opts.id) {
            const state = argsOrState as LBPoolState | undefined;
            inputs["activeMonitorId"] = state ? state.activeMonitorId : undefined;
            inputs["algorithm"] = state ? state.algorithm : undefined;
            inputs["description"] = state ? state.description : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["memberGroup"] = state ? state.memberGroup : undefined;
            inputs["members"] = state ? state.members : undefined;
            inputs["minActiveMembers"] = state ? state.minActiveMembers : undefined;
            inputs["passiveMonitorId"] = state ? state.passiveMonitorId : undefined;
            inputs["revision"] = state ? state.revision : undefined;
            inputs["snatTranslation"] = state ? state.snatTranslation : undefined;
            inputs["tags"] = state ? state.tags : undefined;
            inputs["tcpMultiplexingEnabled"] = state ? state.tcpMultiplexingEnabled : undefined;
            inputs["tcpMultiplexingNumber"] = state ? state.tcpMultiplexingNumber : undefined;
        } else {
            const args = argsOrState as LBPoolArgs | undefined;
            inputs["activeMonitorId"] = args ? args.activeMonitorId : undefined;
            inputs["algorithm"] = args ? args.algorithm : undefined;
            inputs["description"] = args ? args.description : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["memberGroup"] = args ? args.memberGroup : undefined;
            inputs["members"] = args ? args.members : undefined;
            inputs["minActiveMembers"] = args ? args.minActiveMembers : undefined;
            inputs["passiveMonitorId"] = args ? args.passiveMonitorId : undefined;
            inputs["snatTranslation"] = args ? args.snatTranslation : undefined;
            inputs["tags"] = args ? args.tags : undefined;
            inputs["tcpMultiplexingEnabled"] = args ? args.tcpMultiplexingEnabled : undefined;
            inputs["tcpMultiplexingNumber"] = args ? args.tcpMultiplexingNumber : undefined;
            inputs["revision"] = undefined /*out*/;
        }
        if (!opts) {
            opts = {}
        }

        if (!opts.version) {
            opts.version = utilities.getVersion();
        }
        super(LBPool.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering LBPool resources.
 */
export interface LBPoolState {
    /**
     * Active health monitor Id. If one is not set, the active healthchecks will be disabled
     */
    readonly activeMonitorId?: pulumi.Input<string>;
    /**
     * Load balancing algorithm controls how the incoming connections are distributed among the members
     */
    readonly algorithm?: pulumi.Input<string>;
    /**
     * Description of this resource
     */
    readonly description?: pulumi.Input<string>;
    /**
     * The display name of this resource. Defaults to ID if not set
     */
    readonly displayName?: pulumi.Input<string>;
    /**
     * Dynamic pool members for the loadbalancing pool. When member group is defined, members setting should not be specified
     */
    readonly memberGroup?: pulumi.Input<inputs.LBPoolMemberGroup>;
    /**
     * List of server pool members. Each pool member is identified, typically, by an IP address and a port
     */
    readonly members?: pulumi.Input<pulumi.Input<inputs.LBPoolMember>[]>;
    /**
     * The minimum number of members for the pool to be considered active
     */
    readonly minActiveMembers?: pulumi.Input<number>;
    /**
     * Passive health monitor Id. If one is not set, the passive healthchecks will be disabled
     */
    readonly passiveMonitorId?: pulumi.Input<string>;
    /**
     * The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
     * changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
     * operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
     */
    readonly revision?: pulumi.Input<number>;
    /**
     * SNAT translation configuration
     */
    readonly snatTranslation?: pulumi.Input<inputs.LBPoolSnatTranslation>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.LBPoolTag>[]>;
    /**
     * TCP multiplexing allows the same TCP connection between load balancer and the backend server to be used for sending
     * multiple client requests from different client TCP connections
     */
    readonly tcpMultiplexingEnabled?: pulumi.Input<boolean>;
    /**
     * The maximum number of TCP connections per pool that are idly kept alive for sending future client requests
     */
    readonly tcpMultiplexingNumber?: pulumi.Input<number>;
}

/**
 * The set of arguments for constructing a LBPool resource.
 */
export interface LBPoolArgs {
    /**
     * Active health monitor Id. If one is not set, the active healthchecks will be disabled
     */
    readonly activeMonitorId?: pulumi.Input<string>;
    /**
     * Load balancing algorithm controls how the incoming connections are distributed among the members
     */
    readonly algorithm?: pulumi.Input<string>;
    /**
     * Description of this resource
     */
    readonly description?: pulumi.Input<string>;
    /**
     * The display name of this resource. Defaults to ID if not set
     */
    readonly displayName?: pulumi.Input<string>;
    /**
     * Dynamic pool members for the loadbalancing pool. When member group is defined, members setting should not be specified
     */
    readonly memberGroup?: pulumi.Input<inputs.LBPoolMemberGroup>;
    /**
     * List of server pool members. Each pool member is identified, typically, by an IP address and a port
     */
    readonly members?: pulumi.Input<pulumi.Input<inputs.LBPoolMember>[]>;
    /**
     * The minimum number of members for the pool to be considered active
     */
    readonly minActiveMembers?: pulumi.Input<number>;
    /**
     * Passive health monitor Id. If one is not set, the passive healthchecks will be disabled
     */
    readonly passiveMonitorId?: pulumi.Input<string>;
    /**
     * SNAT translation configuration
     */
    readonly snatTranslation?: pulumi.Input<inputs.LBPoolSnatTranslation>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.LBPoolTag>[]>;
    /**
     * TCP multiplexing allows the same TCP connection between load balancer and the backend server to be used for sending
     * multiple client requests from different client TCP connections
     */
    readonly tcpMultiplexingEnabled?: pulumi.Input<boolean>;
    /**
     * The maximum number of TCP connections per pool that are idly kept alive for sending future client requests
     */
    readonly tcpMultiplexingNumber?: pulumi.Input<number>;
}
