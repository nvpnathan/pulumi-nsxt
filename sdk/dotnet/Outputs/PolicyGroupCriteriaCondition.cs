// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt.Outputs
{

    [OutputType]
    public sealed class PolicyGroupCriteriaCondition
    {
        public readonly string Key;
        public readonly string MemberType;
        public readonly string Operator;
        public readonly string Value;

        [OutputConstructor]
        private PolicyGroupCriteriaCondition(
            string key,

            string memberType,

            string @operator,

            string value)
        {
            Key = key;
            MemberType = memberType;
            Operator = @operator;
            Value = value;
        }
    }
}
