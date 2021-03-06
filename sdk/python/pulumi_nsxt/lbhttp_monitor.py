# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Union
from . import utilities, tables


class LBHTTPMonitor(pulumi.CustomResource):
    description: pulumi.Output[str]
    """
    Description of this resource
    """
    display_name: pulumi.Output[str]
    """
    The display name of this resource. Defaults to ID if not set
    """
    fall_count: pulumi.Output[float]
    """
    Number of consecutive checks that must fail before marking it down
    """
    interval: pulumi.Output[float]
    """
    The frequency at which the system issues the monitor check (in seconds)
    """
    monitor_port: pulumi.Output[str]
    """
    If the monitor port is specified, it would override pool member port setting for healthcheck. A port range is not
    supported
    """
    request_body: pulumi.Output[str]
    """
    String to send as HTTP health check request body. Valid only for certain HTTP methods like POST
    """
    request_headers: pulumi.Output[list]
    """
    Array of HTTP request headers

      * `name` (`str`)
      * `value` (`str`)
    """
    request_method: pulumi.Output[str]
    """
    Health check method for HTTP monitor type
    """
    request_url: pulumi.Output[str]
    """
    URL used for HTTP monitor
    """
    request_version: pulumi.Output[str]
    """
    HTTP request version
    """
    response_body: pulumi.Output[str]
    """
    If HTTP specified, healthcheck HTTP response body is matched against the specified string (regular expressions not
    supported), and succeeds only if there is a match
    """
    response_status_codes: pulumi.Output[list]
    """
    The HTTP response status code should be a valid HTTP status code
    """
    revision: pulumi.Output[float]
    """
    The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
    changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
    operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
    """
    rise_count: pulumi.Output[float]
    """
    Number of consecutive checks that must pass before marking it up
    """
    tags: pulumi.Output[list]
    """
    Set of opaque identifiers meaningful to the user

      * `scope` (`str`)
      * `tag` (`str`)
    """
    timeout: pulumi.Output[float]
    """
    Number of seconds the target has to respond to the monitor request
    """
    def __init__(__self__, resource_name, opts=None, description=None, display_name=None, fall_count=None, interval=None, monitor_port=None, request_body=None, request_headers=None, request_method=None, request_url=None, request_version=None, response_body=None, response_status_codes=None, rise_count=None, tags=None, timeout=None, __props__=None, __name__=None, __opts__=None):
        """
        Create a LBHTTPMonitor resource with the given unique name, props, and options.
        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] description: Description of this resource
        :param pulumi.Input[str] display_name: The display name of this resource. Defaults to ID if not set
        :param pulumi.Input[float] fall_count: Number of consecutive checks that must fail before marking it down
        :param pulumi.Input[float] interval: The frequency at which the system issues the monitor check (in seconds)
        :param pulumi.Input[str] monitor_port: If the monitor port is specified, it would override pool member port setting for healthcheck. A port range is not
               supported
        :param pulumi.Input[str] request_body: String to send as HTTP health check request body. Valid only for certain HTTP methods like POST
        :param pulumi.Input[list] request_headers: Array of HTTP request headers
        :param pulumi.Input[str] request_method: Health check method for HTTP monitor type
        :param pulumi.Input[str] request_url: URL used for HTTP monitor
        :param pulumi.Input[str] request_version: HTTP request version
        :param pulumi.Input[str] response_body: If HTTP specified, healthcheck HTTP response body is matched against the specified string (regular expressions not
               supported), and succeeds only if there is a match
        :param pulumi.Input[list] response_status_codes: The HTTP response status code should be a valid HTTP status code
        :param pulumi.Input[float] rise_count: Number of consecutive checks that must pass before marking it up
        :param pulumi.Input[list] tags: Set of opaque identifiers meaningful to the user
        :param pulumi.Input[float] timeout: Number of seconds the target has to respond to the monitor request

        The **request_headers** object supports the following:

          * `name` (`pulumi.Input[str]`)
          * `value` (`pulumi.Input[str]`)

        The **tags** object supports the following:

          * `scope` (`pulumi.Input[str]`)
          * `tag` (`pulumi.Input[str]`)
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

            __props__['description'] = description
            __props__['display_name'] = display_name
            __props__['fall_count'] = fall_count
            __props__['interval'] = interval
            __props__['monitor_port'] = monitor_port
            __props__['request_body'] = request_body
            __props__['request_headers'] = request_headers
            __props__['request_method'] = request_method
            __props__['request_url'] = request_url
            __props__['request_version'] = request_version
            __props__['response_body'] = response_body
            __props__['response_status_codes'] = response_status_codes
            __props__['rise_count'] = rise_count
            __props__['tags'] = tags
            __props__['timeout'] = timeout
            __props__['revision'] = None
        super(LBHTTPMonitor, __self__).__init__(
            'nsxt:index/lBHTTPMonitor:LBHTTPMonitor',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name, id, opts=None, description=None, display_name=None, fall_count=None, interval=None, monitor_port=None, request_body=None, request_headers=None, request_method=None, request_url=None, request_version=None, response_body=None, response_status_codes=None, revision=None, rise_count=None, tags=None, timeout=None):
        """
        Get an existing LBHTTPMonitor resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param str id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] description: Description of this resource
        :param pulumi.Input[str] display_name: The display name of this resource. Defaults to ID if not set
        :param pulumi.Input[float] fall_count: Number of consecutive checks that must fail before marking it down
        :param pulumi.Input[float] interval: The frequency at which the system issues the monitor check (in seconds)
        :param pulumi.Input[str] monitor_port: If the monitor port is specified, it would override pool member port setting for healthcheck. A port range is not
               supported
        :param pulumi.Input[str] request_body: String to send as HTTP health check request body. Valid only for certain HTTP methods like POST
        :param pulumi.Input[list] request_headers: Array of HTTP request headers
        :param pulumi.Input[str] request_method: Health check method for HTTP monitor type
        :param pulumi.Input[str] request_url: URL used for HTTP monitor
        :param pulumi.Input[str] request_version: HTTP request version
        :param pulumi.Input[str] response_body: If HTTP specified, healthcheck HTTP response body is matched against the specified string (regular expressions not
               supported), and succeeds only if there is a match
        :param pulumi.Input[list] response_status_codes: The HTTP response status code should be a valid HTTP status code
        :param pulumi.Input[float] revision: The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
               changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
               operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
        :param pulumi.Input[float] rise_count: Number of consecutive checks that must pass before marking it up
        :param pulumi.Input[list] tags: Set of opaque identifiers meaningful to the user
        :param pulumi.Input[float] timeout: Number of seconds the target has to respond to the monitor request

        The **request_headers** object supports the following:

          * `name` (`pulumi.Input[str]`)
          * `value` (`pulumi.Input[str]`)

        The **tags** object supports the following:

          * `scope` (`pulumi.Input[str]`)
          * `tag` (`pulumi.Input[str]`)
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = dict()

        __props__["description"] = description
        __props__["display_name"] = display_name
        __props__["fall_count"] = fall_count
        __props__["interval"] = interval
        __props__["monitor_port"] = monitor_port
        __props__["request_body"] = request_body
        __props__["request_headers"] = request_headers
        __props__["request_method"] = request_method
        __props__["request_url"] = request_url
        __props__["request_version"] = request_version
        __props__["response_body"] = response_body
        __props__["response_status_codes"] = response_status_codes
        __props__["revision"] = revision
        __props__["rise_count"] = rise_count
        __props__["tags"] = tags
        __props__["timeout"] = timeout
        return LBHTTPMonitor(resource_name, opts=opts, __props__=__props__)

    def translate_output_property(self, prop):
        return tables._CAMEL_TO_SNAKE_CASE_TABLE.get(prop) or prop

    def translate_input_property(self, prop):
        return tables._SNAKE_TO_CAMEL_CASE_TABLE.get(prop) or prop
