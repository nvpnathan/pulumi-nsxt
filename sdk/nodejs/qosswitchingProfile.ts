// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "./types/input";
import * as outputs from "./types/output";
import * as utilities from "./utilities";

export class QOSSwitchingProfile extends pulumi.CustomResource {
    /**
     * Get an existing QOSSwitchingProfile resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: QOSSwitchingProfileState, opts?: pulumi.CustomResourceOptions): QOSSwitchingProfile {
        return new QOSSwitchingProfile(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'nsxt:index/qOSSwitchingProfile:QOSSwitchingProfile';

    /**
     * Returns true if the given object is an instance of QOSSwitchingProfile.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is QOSSwitchingProfile {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === QOSSwitchingProfile.__pulumiType;
    }

    /**
     * Class of service
     */
    public readonly classOfService!: pulumi.Output<number | undefined>;
    /**
     * Description of this resource
     */
    public readonly description!: pulumi.Output<string | undefined>;
    /**
     * The display name of this resource. Defaults to ID if not set
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * DSCP Priority
     */
    public readonly dscpPriority!: pulumi.Output<number | undefined>;
    /**
     * Trust mode for DSCP
     */
    public readonly dscpTrusted!: pulumi.Output<boolean | undefined>;
    public readonly egressRateShaper!: pulumi.Output<outputs.QOSSwitchingProfileEgressRateShaper | undefined>;
    public readonly ingressBroadcastRateShaper!: pulumi.Output<outputs.QOSSwitchingProfileIngressBroadcastRateShaper | undefined>;
    public readonly ingressRateShaper!: pulumi.Output<outputs.QOSSwitchingProfileIngressRateShaper | undefined>;
    /**
     * The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
     * changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
     * operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
     */
    public /*out*/ readonly revision!: pulumi.Output<number>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    public readonly tags!: pulumi.Output<outputs.QOSSwitchingProfileTag[] | undefined>;

    /**
     * Create a QOSSwitchingProfile resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args?: QOSSwitchingProfileArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: QOSSwitchingProfileArgs | QOSSwitchingProfileState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        if (opts && opts.id) {
            const state = argsOrState as QOSSwitchingProfileState | undefined;
            inputs["classOfService"] = state ? state.classOfService : undefined;
            inputs["description"] = state ? state.description : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["dscpPriority"] = state ? state.dscpPriority : undefined;
            inputs["dscpTrusted"] = state ? state.dscpTrusted : undefined;
            inputs["egressRateShaper"] = state ? state.egressRateShaper : undefined;
            inputs["ingressBroadcastRateShaper"] = state ? state.ingressBroadcastRateShaper : undefined;
            inputs["ingressRateShaper"] = state ? state.ingressRateShaper : undefined;
            inputs["revision"] = state ? state.revision : undefined;
            inputs["tags"] = state ? state.tags : undefined;
        } else {
            const args = argsOrState as QOSSwitchingProfileArgs | undefined;
            inputs["classOfService"] = args ? args.classOfService : undefined;
            inputs["description"] = args ? args.description : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["dscpPriority"] = args ? args.dscpPriority : undefined;
            inputs["dscpTrusted"] = args ? args.dscpTrusted : undefined;
            inputs["egressRateShaper"] = args ? args.egressRateShaper : undefined;
            inputs["ingressBroadcastRateShaper"] = args ? args.ingressBroadcastRateShaper : undefined;
            inputs["ingressRateShaper"] = args ? args.ingressRateShaper : undefined;
            inputs["tags"] = args ? args.tags : undefined;
            inputs["revision"] = undefined /*out*/;
        }
        if (!opts) {
            opts = {}
        }

        if (!opts.version) {
            opts.version = utilities.getVersion();
        }
        super(QOSSwitchingProfile.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering QOSSwitchingProfile resources.
 */
export interface QOSSwitchingProfileState {
    /**
     * Class of service
     */
    readonly classOfService?: pulumi.Input<number>;
    /**
     * Description of this resource
     */
    readonly description?: pulumi.Input<string>;
    /**
     * The display name of this resource. Defaults to ID if not set
     */
    readonly displayName?: pulumi.Input<string>;
    /**
     * DSCP Priority
     */
    readonly dscpPriority?: pulumi.Input<number>;
    /**
     * Trust mode for DSCP
     */
    readonly dscpTrusted?: pulumi.Input<boolean>;
    readonly egressRateShaper?: pulumi.Input<inputs.QOSSwitchingProfileEgressRateShaper>;
    readonly ingressBroadcastRateShaper?: pulumi.Input<inputs.QOSSwitchingProfileIngressBroadcastRateShaper>;
    readonly ingressRateShaper?: pulumi.Input<inputs.QOSSwitchingProfileIngressRateShaper>;
    /**
     * The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
     * changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
     * operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
     */
    readonly revision?: pulumi.Input<number>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.QOSSwitchingProfileTag>[]>;
}

/**
 * The set of arguments for constructing a QOSSwitchingProfile resource.
 */
export interface QOSSwitchingProfileArgs {
    /**
     * Class of service
     */
    readonly classOfService?: pulumi.Input<number>;
    /**
     * Description of this resource
     */
    readonly description?: pulumi.Input<string>;
    /**
     * The display name of this resource. Defaults to ID if not set
     */
    readonly displayName?: pulumi.Input<string>;
    /**
     * DSCP Priority
     */
    readonly dscpPriority?: pulumi.Input<number>;
    /**
     * Trust mode for DSCP
     */
    readonly dscpTrusted?: pulumi.Input<boolean>;
    readonly egressRateShaper?: pulumi.Input<inputs.QOSSwitchingProfileEgressRateShaper>;
    readonly ingressBroadcastRateShaper?: pulumi.Input<inputs.QOSSwitchingProfileIngressBroadcastRateShaper>;
    readonly ingressRateShaper?: pulumi.Input<inputs.QOSSwitchingProfileIngressRateShaper>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.QOSSwitchingProfileTag>[]>;
}