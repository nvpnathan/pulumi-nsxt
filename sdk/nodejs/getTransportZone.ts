// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "./types/input";
import * as outputs from "./types/output";
import * as utilities from "./utilities";

export function getTransportZone(args?: GetTransportZoneArgs, opts?: pulumi.InvokeOptions): Promise<GetTransportZoneResult> {
    args = args || {};
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("nsxt:index/getTransportZone:getTransportZone", {
        "description": args.description,
        "displayName": args.displayName,
        "hostSwitchName": args.hostSwitchName,
        "id": args.id,
        "transportType": args.transportType,
    }, opts);
}

/**
 * A collection of arguments for invoking getTransportZone.
 */
export interface GetTransportZoneArgs {
    readonly description?: string;
    readonly displayName?: string;
    readonly hostSwitchName?: string;
    readonly id?: string;
    readonly transportType?: string;
}

/**
 * A collection of values returned by getTransportZone.
 */
export interface GetTransportZoneResult {
    readonly description: string;
    readonly displayName: string;
    readonly hostSwitchName: string;
    readonly id: string;
    readonly transportType: string;
}