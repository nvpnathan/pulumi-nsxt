// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "./types/input";
import * as outputs from "./types/output";
import * as utilities from "./utilities";

export function getPolicyVM(args?: GetPolicyVMArgs, opts?: pulumi.InvokeOptions): Promise<GetPolicyVMResult> {
    args = args || {};
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("nsxt:index/getPolicyVM:getPolicyVM", {
        "biosId": args.biosId,
        "description": args.description,
        "displayName": args.displayName,
        "externalId": args.externalId,
        "instanceId": args.instanceId,
    }, opts);
}

/**
 * A collection of arguments for invoking getPolicyVM.
 */
export interface GetPolicyVMArgs {
    readonly biosId?: string;
    readonly description?: string;
    readonly displayName?: string;
    readonly externalId?: string;
    readonly instanceId?: string;
}

/**
 * A collection of values returned by getPolicyVM.
 */
export interface GetPolicyVMResult {
    readonly biosId: string;
    readonly description: string;
    readonly displayName: string;
    readonly externalId: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly instanceId: string;
}