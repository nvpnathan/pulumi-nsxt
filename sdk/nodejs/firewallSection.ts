// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "./types/input";
import * as outputs from "./types/output";
import * as utilities from "./utilities";

export class FirewallSection extends pulumi.CustomResource {
    /**
     * Get an existing FirewallSection resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: FirewallSectionState, opts?: pulumi.CustomResourceOptions): FirewallSection {
        return new FirewallSection(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'nsxt:index/firewallSection:FirewallSection';

    /**
     * Returns true if the given object is an instance of FirewallSection.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is FirewallSection {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === FirewallSection.__pulumiType;
    }

    /**
     * List of objects where the rules in this section will be enforced. This will take precedence over rule level appliedTo
     */
    public readonly appliedTos!: pulumi.Output<outputs.FirewallSectionAppliedTo[] | undefined>;
    /**
     * Description of this resource
     */
    public readonly description!: pulumi.Output<string | undefined>;
    /**
     * The display name of this resource. Defaults to ID if not set
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * Id of section that should come after this one
     */
    public readonly insertBefore!: pulumi.Output<string | undefined>;
    /**
     * A boolean flag which reflects whether a firewall section is default section or not
     */
    public /*out*/ readonly isDefault!: pulumi.Output<boolean>;
    /**
     * The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
     * changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
     * operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
     */
    public /*out*/ readonly revision!: pulumi.Output<number>;
    /**
     * List of firewall rules in the section. Only homogeneous rules are supported
     */
    public readonly rules!: pulumi.Output<outputs.FirewallSectionRule[] | undefined>;
    /**
     * Type of the rules which a section can contain. Only homogeneous sections are supported
     */
    public readonly sectionType!: pulumi.Output<string>;
    /**
     * Stateful or Stateless nature of firewall section is enforced on all rules inside the section
     */
    public readonly stateful!: pulumi.Output<boolean>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    public readonly tags!: pulumi.Output<outputs.FirewallSectionTag[] | undefined>;

    /**
     * Create a FirewallSection resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: FirewallSectionArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: FirewallSectionArgs | FirewallSectionState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        if (opts && opts.id) {
            const state = argsOrState as FirewallSectionState | undefined;
            inputs["appliedTos"] = state ? state.appliedTos : undefined;
            inputs["description"] = state ? state.description : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["insertBefore"] = state ? state.insertBefore : undefined;
            inputs["isDefault"] = state ? state.isDefault : undefined;
            inputs["revision"] = state ? state.revision : undefined;
            inputs["rules"] = state ? state.rules : undefined;
            inputs["sectionType"] = state ? state.sectionType : undefined;
            inputs["stateful"] = state ? state.stateful : undefined;
            inputs["tags"] = state ? state.tags : undefined;
        } else {
            const args = argsOrState as FirewallSectionArgs | undefined;
            if (!args || args.sectionType === undefined) {
                throw new Error("Missing required property 'sectionType'");
            }
            if (!args || args.stateful === undefined) {
                throw new Error("Missing required property 'stateful'");
            }
            inputs["appliedTos"] = args ? args.appliedTos : undefined;
            inputs["description"] = args ? args.description : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["insertBefore"] = args ? args.insertBefore : undefined;
            inputs["rules"] = args ? args.rules : undefined;
            inputs["sectionType"] = args ? args.sectionType : undefined;
            inputs["stateful"] = args ? args.stateful : undefined;
            inputs["tags"] = args ? args.tags : undefined;
            inputs["isDefault"] = undefined /*out*/;
            inputs["revision"] = undefined /*out*/;
        }
        if (!opts) {
            opts = {}
        }

        if (!opts.version) {
            opts.version = utilities.getVersion();
        }
        super(FirewallSection.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering FirewallSection resources.
 */
export interface FirewallSectionState {
    /**
     * List of objects where the rules in this section will be enforced. This will take precedence over rule level appliedTo
     */
    readonly appliedTos?: pulumi.Input<pulumi.Input<inputs.FirewallSectionAppliedTo>[]>;
    /**
     * Description of this resource
     */
    readonly description?: pulumi.Input<string>;
    /**
     * The display name of this resource. Defaults to ID if not set
     */
    readonly displayName?: pulumi.Input<string>;
    /**
     * Id of section that should come after this one
     */
    readonly insertBefore?: pulumi.Input<string>;
    /**
     * A boolean flag which reflects whether a firewall section is default section or not
     */
    readonly isDefault?: pulumi.Input<boolean>;
    /**
     * The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
     * changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
     * operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
     */
    readonly revision?: pulumi.Input<number>;
    /**
     * List of firewall rules in the section. Only homogeneous rules are supported
     */
    readonly rules?: pulumi.Input<pulumi.Input<inputs.FirewallSectionRule>[]>;
    /**
     * Type of the rules which a section can contain. Only homogeneous sections are supported
     */
    readonly sectionType?: pulumi.Input<string>;
    /**
     * Stateful or Stateless nature of firewall section is enforced on all rules inside the section
     */
    readonly stateful?: pulumi.Input<boolean>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.FirewallSectionTag>[]>;
}

/**
 * The set of arguments for constructing a FirewallSection resource.
 */
export interface FirewallSectionArgs {
    /**
     * List of objects where the rules in this section will be enforced. This will take precedence over rule level appliedTo
     */
    readonly appliedTos?: pulumi.Input<pulumi.Input<inputs.FirewallSectionAppliedTo>[]>;
    /**
     * Description of this resource
     */
    readonly description?: pulumi.Input<string>;
    /**
     * The display name of this resource. Defaults to ID if not set
     */
    readonly displayName?: pulumi.Input<string>;
    /**
     * Id of section that should come after this one
     */
    readonly insertBefore?: pulumi.Input<string>;
    /**
     * List of firewall rules in the section. Only homogeneous rules are supported
     */
    readonly rules?: pulumi.Input<pulumi.Input<inputs.FirewallSectionRule>[]>;
    /**
     * Type of the rules which a section can contain. Only homogeneous sections are supported
     */
    readonly sectionType: pulumi.Input<string>;
    /**
     * Stateful or Stateless nature of firewall section is enforced on all rules inside the section
     */
    readonly stateful: pulumi.Input<boolean>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.FirewallSectionTag>[]>;
}
