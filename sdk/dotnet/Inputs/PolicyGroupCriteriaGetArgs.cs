// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt.Inputs
{

    public sealed class PolicyGroupCriteriaGetArgs : Pulumi.ResourceArgs
    {
        [Input("conditions")]
        private InputList<Inputs.PolicyGroupCriteriaConditionGetArgs>? _conditions;
        public InputList<Inputs.PolicyGroupCriteriaConditionGetArgs> Conditions
        {
            get => _conditions ?? (_conditions = new InputList<Inputs.PolicyGroupCriteriaConditionGetArgs>());
            set => _conditions = value;
        }

        [Input("ipaddressExpression")]
        public Input<Inputs.PolicyGroupCriteriaIpaddressExpressionGetArgs>? IpaddressExpression { get; set; }

        [Input("macaddressExpression")]
        public Input<Inputs.PolicyGroupCriteriaMacaddressExpressionGetArgs>? MacaddressExpression { get; set; }

        [Input("pathExpression")]
        public Input<Inputs.PolicyGroupCriteriaPathExpressionGetArgs>? PathExpression { get; set; }

        public PolicyGroupCriteriaGetArgs()
        {
        }
    }
}
