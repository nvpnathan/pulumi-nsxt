// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "./types/input";
import * as outputs from "./types/output";
import * as utilities from "./utilities";

export class LogicalSwitch extends pulumi.CustomResource {
    /**
     * Get an existing LogicalSwitch resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: LogicalSwitchState, opts?: pulumi.CustomResourceOptions): LogicalSwitch {
        return new LogicalSwitch(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'nsxt:index/logicalSwitch:LogicalSwitch';

    /**
     * Returns true if the given object is an instance of LogicalSwitch.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is LogicalSwitch {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === LogicalSwitch.__pulumiType;
    }

    /**
     * Address bindings for the Logical switch
     */
    public readonly addressBindings!: pulumi.Output<outputs.LogicalSwitchAddressBinding[] | undefined>;
    /**
     * Represents Desired state of the object
     */
    public readonly adminState!: pulumi.Output<string | undefined>;
    /**
     * Description of this resource
     */
    public readonly description!: pulumi.Output<string | undefined>;
    /**
     * The display name of this resource. Defaults to ID if not set
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * IP pool id that associated with a LogicalSwitch
     */
    public readonly ipPoolId!: pulumi.Output<string | undefined>;
    /**
     * Mac pool id that associated with a LogicalSwitch
     */
    public readonly macPoolId!: pulumi.Output<string | undefined>;
    /**
     * Replication mode of the Logical Switch
     */
    public readonly replicationMode!: pulumi.Output<string | undefined>;
    /**
     * The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
     * changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
     * operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
     */
    public /*out*/ readonly revision!: pulumi.Output<number>;
    /**
     * List of IDs of switching profiles (of various types) to be associated with this object. Default switching profiles will
     * be used if not specified
     */
    public readonly switchingProfileIds!: pulumi.Output<outputs.LogicalSwitchSwitchingProfileId[] | undefined>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    public readonly tags!: pulumi.Output<outputs.LogicalSwitchTag[] | undefined>;
    /**
     * Id of the TransportZone to which this LogicalSwitch is associated
     */
    public readonly transportZoneId!: pulumi.Output<string>;
    /**
     * @deprecated Use nsxt_vlan_logical_switch resource instead
     */
    public readonly vlan!: pulumi.Output<number | undefined>;
    /**
     * VNI for this LogicalSwitch
     */
    public readonly vni!: pulumi.Output<number>;

    /**
     * Create a LogicalSwitch resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: LogicalSwitchArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: LogicalSwitchArgs | LogicalSwitchState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        if (opts && opts.id) {
            const state = argsOrState as LogicalSwitchState | undefined;
            inputs["addressBindings"] = state ? state.addressBindings : undefined;
            inputs["adminState"] = state ? state.adminState : undefined;
            inputs["description"] = state ? state.description : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["ipPoolId"] = state ? state.ipPoolId : undefined;
            inputs["macPoolId"] = state ? state.macPoolId : undefined;
            inputs["replicationMode"] = state ? state.replicationMode : undefined;
            inputs["revision"] = state ? state.revision : undefined;
            inputs["switchingProfileIds"] = state ? state.switchingProfileIds : undefined;
            inputs["tags"] = state ? state.tags : undefined;
            inputs["transportZoneId"] = state ? state.transportZoneId : undefined;
            inputs["vlan"] = state ? state.vlan : undefined;
            inputs["vni"] = state ? state.vni : undefined;
        } else {
            const args = argsOrState as LogicalSwitchArgs | undefined;
            if (!args || args.transportZoneId === undefined) {
                throw new Error("Missing required property 'transportZoneId'");
            }
            inputs["addressBindings"] = args ? args.addressBindings : undefined;
            inputs["adminState"] = args ? args.adminState : undefined;
            inputs["description"] = args ? args.description : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["ipPoolId"] = args ? args.ipPoolId : undefined;
            inputs["macPoolId"] = args ? args.macPoolId : undefined;
            inputs["replicationMode"] = args ? args.replicationMode : undefined;
            inputs["switchingProfileIds"] = args ? args.switchingProfileIds : undefined;
            inputs["tags"] = args ? args.tags : undefined;
            inputs["transportZoneId"] = args ? args.transportZoneId : undefined;
            inputs["vlan"] = args ? args.vlan : undefined;
            inputs["vni"] = args ? args.vni : undefined;
            inputs["revision"] = undefined /*out*/;
        }
        if (!opts) {
            opts = {}
        }

        if (!opts.version) {
            opts.version = utilities.getVersion();
        }
        super(LogicalSwitch.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering LogicalSwitch resources.
 */
export interface LogicalSwitchState {
    /**
     * Address bindings for the Logical switch
     */
    readonly addressBindings?: pulumi.Input<pulumi.Input<inputs.LogicalSwitchAddressBinding>[]>;
    /**
     * Represents Desired state of the object
     */
    readonly adminState?: pulumi.Input<string>;
    /**
     * Description of this resource
     */
    readonly description?: pulumi.Input<string>;
    /**
     * The display name of this resource. Defaults to ID if not set
     */
    readonly displayName?: pulumi.Input<string>;
    /**
     * IP pool id that associated with a LogicalSwitch
     */
    readonly ipPoolId?: pulumi.Input<string>;
    /**
     * Mac pool id that associated with a LogicalSwitch
     */
    readonly macPoolId?: pulumi.Input<string>;
    /**
     * Replication mode of the Logical Switch
     */
    readonly replicationMode?: pulumi.Input<string>;
    /**
     * The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
     * changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
     * operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
     */
    readonly revision?: pulumi.Input<number>;
    /**
     * List of IDs of switching profiles (of various types) to be associated with this object. Default switching profiles will
     * be used if not specified
     */
    readonly switchingProfileIds?: pulumi.Input<pulumi.Input<inputs.LogicalSwitchSwitchingProfileId>[]>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.LogicalSwitchTag>[]>;
    /**
     * Id of the TransportZone to which this LogicalSwitch is associated
     */
    readonly transportZoneId?: pulumi.Input<string>;
    /**
     * @deprecated Use nsxt_vlan_logical_switch resource instead
     */
    readonly vlan?: pulumi.Input<number>;
    /**
     * VNI for this LogicalSwitch
     */
    readonly vni?: pulumi.Input<number>;
}

/**
 * The set of arguments for constructing a LogicalSwitch resource.
 */
export interface LogicalSwitchArgs {
    /**
     * Address bindings for the Logical switch
     */
    readonly addressBindings?: pulumi.Input<pulumi.Input<inputs.LogicalSwitchAddressBinding>[]>;
    /**
     * Represents Desired state of the object
     */
    readonly adminState?: pulumi.Input<string>;
    /**
     * Description of this resource
     */
    readonly description?: pulumi.Input<string>;
    /**
     * The display name of this resource. Defaults to ID if not set
     */
    readonly displayName?: pulumi.Input<string>;
    /**
     * IP pool id that associated with a LogicalSwitch
     */
    readonly ipPoolId?: pulumi.Input<string>;
    /**
     * Mac pool id that associated with a LogicalSwitch
     */
    readonly macPoolId?: pulumi.Input<string>;
    /**
     * Replication mode of the Logical Switch
     */
    readonly replicationMode?: pulumi.Input<string>;
    /**
     * List of IDs of switching profiles (of various types) to be associated with this object. Default switching profiles will
     * be used if not specified
     */
    readonly switchingProfileIds?: pulumi.Input<pulumi.Input<inputs.LogicalSwitchSwitchingProfileId>[]>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.LogicalSwitchTag>[]>;
    /**
     * Id of the TransportZone to which this LogicalSwitch is associated
     */
    readonly transportZoneId: pulumi.Input<string>;
    /**
     * @deprecated Use nsxt_vlan_logical_switch resource instead
     */
    readonly vlan?: pulumi.Input<number>;
    /**
     * VNI for this LogicalSwitch
     */
    readonly vni?: pulumi.Input<number>;
}
