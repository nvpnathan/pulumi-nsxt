// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "./types/input";
import * as outputs from "./types/output";
import * as utilities from "./utilities";

export class LBService extends pulumi.CustomResource {
    /**
     * Get an existing LBService resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: LBServiceState, opts?: pulumi.CustomResourceOptions): LBService {
        return new LBService(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'nsxt:index/lBService:LBService';

    /**
     * Returns true if the given object is an instance of LBService.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is LBService {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === LBService.__pulumiType;
    }

    /**
     * Description of this resource
     */
    public readonly description!: pulumi.Output<string | undefined>;
    /**
     * The display name of this resource. Defaults to ID if not set
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * Whether the load balancer service is enabled
     */
    public readonly enabled!: pulumi.Output<boolean | undefined>;
    /**
     * Load balancer engine writes information about encountered issues of different severity levels to the error log. This
     * setting is used to define the severity level of the error log
     */
    public readonly errorLogLevel!: pulumi.Output<string | undefined>;
    /**
     * Logical Tier1 Router to which the Load Balancer is to be attached
     */
    public readonly logicalRouterId!: pulumi.Output<string>;
    /**
     * The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
     * changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
     * operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
     */
    public /*out*/ readonly revision!: pulumi.Output<number>;
    /**
     * Size of load balancer service
     */
    public readonly size!: pulumi.Output<string | undefined>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    public readonly tags!: pulumi.Output<outputs.LBServiceTag[] | undefined>;
    /**
     * Virtual servers associated with this Load Balancer
     */
    public readonly virtualServerIds!: pulumi.Output<string[] | undefined>;

    /**
     * Create a LBService resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: LBServiceArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: LBServiceArgs | LBServiceState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        if (opts && opts.id) {
            const state = argsOrState as LBServiceState | undefined;
            inputs["description"] = state ? state.description : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["enabled"] = state ? state.enabled : undefined;
            inputs["errorLogLevel"] = state ? state.errorLogLevel : undefined;
            inputs["logicalRouterId"] = state ? state.logicalRouterId : undefined;
            inputs["revision"] = state ? state.revision : undefined;
            inputs["size"] = state ? state.size : undefined;
            inputs["tags"] = state ? state.tags : undefined;
            inputs["virtualServerIds"] = state ? state.virtualServerIds : undefined;
        } else {
            const args = argsOrState as LBServiceArgs | undefined;
            if (!args || args.logicalRouterId === undefined) {
                throw new Error("Missing required property 'logicalRouterId'");
            }
            inputs["description"] = args ? args.description : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["enabled"] = args ? args.enabled : undefined;
            inputs["errorLogLevel"] = args ? args.errorLogLevel : undefined;
            inputs["logicalRouterId"] = args ? args.logicalRouterId : undefined;
            inputs["size"] = args ? args.size : undefined;
            inputs["tags"] = args ? args.tags : undefined;
            inputs["virtualServerIds"] = args ? args.virtualServerIds : undefined;
            inputs["revision"] = undefined /*out*/;
        }
        if (!opts) {
            opts = {}
        }

        if (!opts.version) {
            opts.version = utilities.getVersion();
        }
        super(LBService.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering LBService resources.
 */
export interface LBServiceState {
    /**
     * Description of this resource
     */
    readonly description?: pulumi.Input<string>;
    /**
     * The display name of this resource. Defaults to ID if not set
     */
    readonly displayName?: pulumi.Input<string>;
    /**
     * Whether the load balancer service is enabled
     */
    readonly enabled?: pulumi.Input<boolean>;
    /**
     * Load balancer engine writes information about encountered issues of different severity levels to the error log. This
     * setting is used to define the severity level of the error log
     */
    readonly errorLogLevel?: pulumi.Input<string>;
    /**
     * Logical Tier1 Router to which the Load Balancer is to be attached
     */
    readonly logicalRouterId?: pulumi.Input<string>;
    /**
     * The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
     * changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
     * operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
     */
    readonly revision?: pulumi.Input<number>;
    /**
     * Size of load balancer service
     */
    readonly size?: pulumi.Input<string>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.LBServiceTag>[]>;
    /**
     * Virtual servers associated with this Load Balancer
     */
    readonly virtualServerIds?: pulumi.Input<pulumi.Input<string>[]>;
}

/**
 * The set of arguments for constructing a LBService resource.
 */
export interface LBServiceArgs {
    /**
     * Description of this resource
     */
    readonly description?: pulumi.Input<string>;
    /**
     * The display name of this resource. Defaults to ID if not set
     */
    readonly displayName?: pulumi.Input<string>;
    /**
     * Whether the load balancer service is enabled
     */
    readonly enabled?: pulumi.Input<boolean>;
    /**
     * Load balancer engine writes information about encountered issues of different severity levels to the error log. This
     * setting is used to define the severity level of the error log
     */
    readonly errorLogLevel?: pulumi.Input<string>;
    /**
     * Logical Tier1 Router to which the Load Balancer is to be attached
     */
    readonly logicalRouterId: pulumi.Input<string>;
    /**
     * Size of load balancer service
     */
    readonly size?: pulumi.Input<string>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.LBServiceTag>[]>;
    /**
     * Virtual servers associated with this Load Balancer
     */
    readonly virtualServerIds?: pulumi.Input<pulumi.Input<string>[]>;
}