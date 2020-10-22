# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Union
from . import utilities, tables


class PolicyTier0GatewayHAVIPConfig(pulumi.CustomResource):
    configs: pulumi.Output[list]
    """
    Tier0 HA VIP Config

      * `enabled` (`bool`)
      * `externalInterfacePaths` (`list`)
      * `vipSubnets` (`list`)
    """
    locale_service_id: pulumi.Output[str]
    """
    Id of associated Gateway Locale Service on NSX
    """
    tier0_id: pulumi.Output[str]
    """
    Id of associated Tier0 Gateway on NSX
    """
    def __init__(__self__, resource_name, opts=None, configs=None, __props__=None, __name__=None, __opts__=None):
        """
        Create a PolicyTier0GatewayHAVIPConfig resource with the given unique name, props, and options.
        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[list] configs: Tier0 HA VIP Config

        The **configs** object supports the following:

          * `enabled` (`pulumi.Input[bool]`)
          * `externalInterfacePaths` (`pulumi.Input[list]`)
          * `vipSubnets` (`pulumi.Input[list]`)
        """
        if __name__ is not None:
            warnings.warn("explicit use of __name__ is deprecated", DeprecationWarning)
            resource_name = __name__
        if __opts__ is not None:
            warnings.warn("explicit use of __opts__ is deprecated, use 'opts' instead", DeprecationWarning)
            opts = __opts__
        if opts is None:
            opts = pulumi.ResourceOptions()
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.version is None:
            opts.version = utilities.get_version()
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = dict()

            if configs is None:
                raise TypeError("Missing required property 'configs'")
            __props__['configs'] = configs
            __props__['locale_service_id'] = None
            __props__['tier0_id'] = None
        super(PolicyTier0GatewayHAVIPConfig, __self__).__init__(
            'nsxt:index/policyTier0GatewayHAVIPConfig:PolicyTier0GatewayHAVIPConfig',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name, id, opts=None, configs=None, locale_service_id=None, tier0_id=None):
        """
        Get an existing PolicyTier0GatewayHAVIPConfig resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param str id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[list] configs: Tier0 HA VIP Config
        :param pulumi.Input[str] locale_service_id: Id of associated Gateway Locale Service on NSX
        :param pulumi.Input[str] tier0_id: Id of associated Tier0 Gateway on NSX

        The **configs** object supports the following:

          * `enabled` (`pulumi.Input[bool]`)
          * `externalInterfacePaths` (`pulumi.Input[list]`)
          * `vipSubnets` (`pulumi.Input[list]`)
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = dict()

        __props__["configs"] = configs
        __props__["locale_service_id"] = locale_service_id
        __props__["tier0_id"] = tier0_id
        return PolicyTier0GatewayHAVIPConfig(resource_name, opts=opts, __props__=__props__)

    def translate_output_property(self, prop):
        return tables._CAMEL_TO_SNAKE_CASE_TABLE.get(prop) or prop

    def translate_input_property(self, prop):
        return tables._SNAKE_TO_CAMEL_CASE_TABLE.get(prop) or prop
