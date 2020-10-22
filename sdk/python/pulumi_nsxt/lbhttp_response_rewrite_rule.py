# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Union
from . import utilities, tables


class LBHTTPResponseRewriteRule(pulumi.CustomResource):
    cookie_conditions: pulumi.Output[list]
    """
    Rule condition based on http header

      * `caseSensitive` (`bool`)
      * `inverse` (`bool`)
      * `matchType` (`str`)
      * `name` (`str`)
      * `value` (`str`)
    """
    description: pulumi.Output[str]
    """
    Description of this resource
    """
    display_name: pulumi.Output[str]
    """
    The display name of this resource. Defaults to ID if not set
    """
    header_rewrite_action: pulumi.Output[dict]
    """
    Header to replace original header in outgoing message

      * `name` (`str`)
      * `value` (`str`)
    """
    ip_conditions: pulumi.Output[list]
    """
    Rule condition based on IP settings of the message

      * `inverse` (`bool`)
      * `sourceAddress` (`str`)
    """
    match_strategy: pulumi.Output[str]
    """
    Strategy when multiple match conditions are specified in one rule (ANY vs ALL)
    """
    method_conditions: pulumi.Output[list]
    """
    Rule condition based on http request method

      * `inverse` (`bool`)
      * `method` (`str`)
    """
    request_header_conditions: pulumi.Output[list]
    """
    Rule condition based on http header

      * `caseSensitive` (`bool`)
      * `inverse` (`bool`)
      * `matchType` (`str`)
      * `name` (`str`)
      * `value` (`str`)
    """
    response_header_conditions: pulumi.Output[list]
    """
    Rule condition based on http header

      * `caseSensitive` (`bool`)
      * `inverse` (`bool`)
      * `matchType` (`str`)
      * `name` (`str`)
      * `value` (`str`)
    """
    revision: pulumi.Output[float]
    """
    The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
    changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
    operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
    """
    tags: pulumi.Output[list]
    """
    Set of opaque identifiers meaningful to the user

      * `scope` (`str`)
      * `tag` (`str`)
    """
    tcp_conditions: pulumi.Output[list]
    """
    Rule condition based on TCP settings of the message

      * `inverse` (`bool`)
      * `sourcePort` (`str`)
    """
    uri_arguments_conditions: pulumi.Output[list]
    """
    Rule condition based on http request URI arguments (query string)

      * `caseSensitive` (`bool`)
      * `inverse` (`bool`)
      * `matchType` (`str`)
      * `uriArguments` (`str`)
    """
    uri_conditions: pulumi.Output[list]
    """
    Rule condition based on http request URI

      * `caseSensitive` (`bool`)
      * `inverse` (`bool`)
      * `matchType` (`str`)
      * `uri` (`str`)
    """
    version_condition: pulumi.Output[dict]
    """
    Rule condition based on http request version

      * `inverse` (`bool`)
      * `version` (`str`)
    """
    def __init__(__self__, resource_name, opts=None, cookie_conditions=None, description=None, display_name=None, header_rewrite_action=None, ip_conditions=None, match_strategy=None, method_conditions=None, request_header_conditions=None, response_header_conditions=None, tags=None, tcp_conditions=None, uri_arguments_conditions=None, uri_conditions=None, version_condition=None, __props__=None, __name__=None, __opts__=None):
        """
        Create a LBHTTPResponseRewriteRule resource with the given unique name, props, and options.
        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[list] cookie_conditions: Rule condition based on http header
        :param pulumi.Input[str] description: Description of this resource
        :param pulumi.Input[str] display_name: The display name of this resource. Defaults to ID if not set
        :param pulumi.Input[dict] header_rewrite_action: Header to replace original header in outgoing message
        :param pulumi.Input[list] ip_conditions: Rule condition based on IP settings of the message
        :param pulumi.Input[str] match_strategy: Strategy when multiple match conditions are specified in one rule (ANY vs ALL)
        :param pulumi.Input[list] method_conditions: Rule condition based on http request method
        :param pulumi.Input[list] request_header_conditions: Rule condition based on http header
        :param pulumi.Input[list] response_header_conditions: Rule condition based on http header
        :param pulumi.Input[list] tags: Set of opaque identifiers meaningful to the user
        :param pulumi.Input[list] tcp_conditions: Rule condition based on TCP settings of the message
        :param pulumi.Input[list] uri_arguments_conditions: Rule condition based on http request URI arguments (query string)
        :param pulumi.Input[list] uri_conditions: Rule condition based on http request URI
        :param pulumi.Input[dict] version_condition: Rule condition based on http request version

        The **cookie_conditions** object supports the following:

          * `caseSensitive` (`pulumi.Input[bool]`)
          * `inverse` (`pulumi.Input[bool]`)
          * `matchType` (`pulumi.Input[str]`)
          * `name` (`pulumi.Input[str]`)
          * `value` (`pulumi.Input[str]`)

        The **header_rewrite_action** object supports the following:

          * `name` (`pulumi.Input[str]`)
          * `value` (`pulumi.Input[str]`)

        The **ip_conditions** object supports the following:

          * `inverse` (`pulumi.Input[bool]`)
          * `sourceAddress` (`pulumi.Input[str]`)

        The **method_conditions** object supports the following:

          * `inverse` (`pulumi.Input[bool]`)
          * `method` (`pulumi.Input[str]`)

        The **request_header_conditions** object supports the following:

          * `caseSensitive` (`pulumi.Input[bool]`)
          * `inverse` (`pulumi.Input[bool]`)
          * `matchType` (`pulumi.Input[str]`)
          * `name` (`pulumi.Input[str]`)
          * `value` (`pulumi.Input[str]`)

        The **response_header_conditions** object supports the following:

          * `caseSensitive` (`pulumi.Input[bool]`)
          * `inverse` (`pulumi.Input[bool]`)
          * `matchType` (`pulumi.Input[str]`)
          * `name` (`pulumi.Input[str]`)
          * `value` (`pulumi.Input[str]`)

        The **tags** object supports the following:

          * `scope` (`pulumi.Input[str]`)
          * `tag` (`pulumi.Input[str]`)

        The **tcp_conditions** object supports the following:

          * `inverse` (`pulumi.Input[bool]`)
          * `sourcePort` (`pulumi.Input[str]`)

        The **uri_arguments_conditions** object supports the following:

          * `caseSensitive` (`pulumi.Input[bool]`)
          * `inverse` (`pulumi.Input[bool]`)
          * `matchType` (`pulumi.Input[str]`)
          * `uriArguments` (`pulumi.Input[str]`)

        The **uri_conditions** object supports the following:

          * `caseSensitive` (`pulumi.Input[bool]`)
          * `inverse` (`pulumi.Input[bool]`)
          * `matchType` (`pulumi.Input[str]`)
          * `uri` (`pulumi.Input[str]`)

        The **version_condition** object supports the following:

          * `inverse` (`pulumi.Input[bool]`)
          * `version` (`pulumi.Input[str]`)
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

            __props__['cookie_conditions'] = cookie_conditions
            __props__['description'] = description
            __props__['display_name'] = display_name
            if header_rewrite_action is None:
                raise TypeError("Missing required property 'header_rewrite_action'")
            __props__['header_rewrite_action'] = header_rewrite_action
            __props__['ip_conditions'] = ip_conditions
            __props__['match_strategy'] = match_strategy
            __props__['method_conditions'] = method_conditions
            __props__['request_header_conditions'] = request_header_conditions
            __props__['response_header_conditions'] = response_header_conditions
            __props__['tags'] = tags
            __props__['tcp_conditions'] = tcp_conditions
            __props__['uri_arguments_conditions'] = uri_arguments_conditions
            __props__['uri_conditions'] = uri_conditions
            __props__['version_condition'] = version_condition
            __props__['revision'] = None
        super(LBHTTPResponseRewriteRule, __self__).__init__(
            'nsxt:index/lBHTTPResponseRewriteRule:LBHTTPResponseRewriteRule',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name, id, opts=None, cookie_conditions=None, description=None, display_name=None, header_rewrite_action=None, ip_conditions=None, match_strategy=None, method_conditions=None, request_header_conditions=None, response_header_conditions=None, revision=None, tags=None, tcp_conditions=None, uri_arguments_conditions=None, uri_conditions=None, version_condition=None):
        """
        Get an existing LBHTTPResponseRewriteRule resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param str id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[list] cookie_conditions: Rule condition based on http header
        :param pulumi.Input[str] description: Description of this resource
        :param pulumi.Input[str] display_name: The display name of this resource. Defaults to ID if not set
        :param pulumi.Input[dict] header_rewrite_action: Header to replace original header in outgoing message
        :param pulumi.Input[list] ip_conditions: Rule condition based on IP settings of the message
        :param pulumi.Input[str] match_strategy: Strategy when multiple match conditions are specified in one rule (ANY vs ALL)
        :param pulumi.Input[list] method_conditions: Rule condition based on http request method
        :param pulumi.Input[list] request_header_conditions: Rule condition based on http header
        :param pulumi.Input[list] response_header_conditions: Rule condition based on http header
        :param pulumi.Input[float] revision: The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
               changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
               operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
        :param pulumi.Input[list] tags: Set of opaque identifiers meaningful to the user
        :param pulumi.Input[list] tcp_conditions: Rule condition based on TCP settings of the message
        :param pulumi.Input[list] uri_arguments_conditions: Rule condition based on http request URI arguments (query string)
        :param pulumi.Input[list] uri_conditions: Rule condition based on http request URI
        :param pulumi.Input[dict] version_condition: Rule condition based on http request version

        The **cookie_conditions** object supports the following:

          * `caseSensitive` (`pulumi.Input[bool]`)
          * `inverse` (`pulumi.Input[bool]`)
          * `matchType` (`pulumi.Input[str]`)
          * `name` (`pulumi.Input[str]`)
          * `value` (`pulumi.Input[str]`)

        The **header_rewrite_action** object supports the following:

          * `name` (`pulumi.Input[str]`)
          * `value` (`pulumi.Input[str]`)

        The **ip_conditions** object supports the following:

          * `inverse` (`pulumi.Input[bool]`)
          * `sourceAddress` (`pulumi.Input[str]`)

        The **method_conditions** object supports the following:

          * `inverse` (`pulumi.Input[bool]`)
          * `method` (`pulumi.Input[str]`)

        The **request_header_conditions** object supports the following:

          * `caseSensitive` (`pulumi.Input[bool]`)
          * `inverse` (`pulumi.Input[bool]`)
          * `matchType` (`pulumi.Input[str]`)
          * `name` (`pulumi.Input[str]`)
          * `value` (`pulumi.Input[str]`)

        The **response_header_conditions** object supports the following:

          * `caseSensitive` (`pulumi.Input[bool]`)
          * `inverse` (`pulumi.Input[bool]`)
          * `matchType` (`pulumi.Input[str]`)
          * `name` (`pulumi.Input[str]`)
          * `value` (`pulumi.Input[str]`)

        The **tags** object supports the following:

          * `scope` (`pulumi.Input[str]`)
          * `tag` (`pulumi.Input[str]`)

        The **tcp_conditions** object supports the following:

          * `inverse` (`pulumi.Input[bool]`)
          * `sourcePort` (`pulumi.Input[str]`)

        The **uri_arguments_conditions** object supports the following:

          * `caseSensitive` (`pulumi.Input[bool]`)
          * `inverse` (`pulumi.Input[bool]`)
          * `matchType` (`pulumi.Input[str]`)
          * `uriArguments` (`pulumi.Input[str]`)

        The **uri_conditions** object supports the following:

          * `caseSensitive` (`pulumi.Input[bool]`)
          * `inverse` (`pulumi.Input[bool]`)
          * `matchType` (`pulumi.Input[str]`)
          * `uri` (`pulumi.Input[str]`)

        The **version_condition** object supports the following:

          * `inverse` (`pulumi.Input[bool]`)
          * `version` (`pulumi.Input[str]`)
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = dict()

        __props__["cookie_conditions"] = cookie_conditions
        __props__["description"] = description
        __props__["display_name"] = display_name
        __props__["header_rewrite_action"] = header_rewrite_action
        __props__["ip_conditions"] = ip_conditions
        __props__["match_strategy"] = match_strategy
        __props__["method_conditions"] = method_conditions
        __props__["request_header_conditions"] = request_header_conditions
        __props__["response_header_conditions"] = response_header_conditions
        __props__["revision"] = revision
        __props__["tags"] = tags
        __props__["tcp_conditions"] = tcp_conditions
        __props__["uri_arguments_conditions"] = uri_arguments_conditions
        __props__["uri_conditions"] = uri_conditions
        __props__["version_condition"] = version_condition
        return LBHTTPResponseRewriteRule(resource_name, opts=opts, __props__=__props__)

    def translate_output_property(self, prop):
        return tables._CAMEL_TO_SNAKE_CASE_TABLE.get(prop) or prop

    def translate_input_property(self, prop):
        return tables._SNAKE_TO_CAMEL_CASE_TABLE.get(prop) or prop
