// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "./types/input";
import * as outputs from "./types/output";
import * as utilities from "./utilities";

export function getPolicyLBMonitor(args?: GetPolicyLBMonitorArgs, opts?: pulumi.InvokeOptions): Promise<GetPolicyLBMonitorResult> {
    args = args || {};
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("nsxt:index/getPolicyLBMonitor:getPolicyLBMonitor", {
        "description": args.description,
        "displayName": args.displayName,
        "id": args.id,
        "type": args.type,
    }, opts);
}

/**
 * A collection of arguments for invoking getPolicyLBMonitor.
 */
export interface GetPolicyLBMonitorArgs {
    readonly description?: string;
    readonly displayName?: string;
    readonly id?: string;
    readonly type?: string;
}

/**
 * A collection of values returned by getPolicyLBMonitor.
 */
export interface GetPolicyLBMonitorResult {
    readonly description: string;
    readonly displayName: string;
    readonly id: string;
    readonly path: string;
    readonly type?: string;
}