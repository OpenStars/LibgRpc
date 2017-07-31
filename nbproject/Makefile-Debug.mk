#
# Generated Makefile - do not edit!
#
# Edit the Makefile in the project folder instead (../Makefile). Each target
# has a -pre and a -post target defined where you can add customized code.
#
# This makefile implements configuration specific macros and targets.


# Environment
MKDIR=mkdir
CP=cp
GREP=grep
NM=nm
CCADMIN=CCadmin
RANLIB=ranlib
CC=gcc
CCC=g++
CXX=g++
FC=gfortran
AS=as

# Macros
CND_PLATFORM=GNU-Linux
CND_DLIB_EXT=so
CND_CONF=Debug
CND_DISTDIR=dist
CND_BUILDDIR=build

# Include project Makefile
include Makefile

# Object Directory
OBJECTDIR=${CND_BUILDDIR}/${CND_CONF}/${CND_PLATFORM}

# Object Files
OBJECTFILES= \
	${OBJECTDIR}/gens/src/proto/grpc/health/v1/health.grpc.pb.o \
	${OBJECTDIR}/gens/src/proto/grpc/health/v1/health.pb.o \
	${OBJECTDIR}/gens/src/proto/grpc/reflection/v1alpha/reflection.grpc.pb.o \
	${OBJECTDIR}/gens/src/proto/grpc/reflection/v1alpha/reflection.pb.o \
	${OBJECTDIR}/gens/src/proto/grpc/status/status.grpc.pb.o \
	${OBJECTDIR}/gens/src/proto/grpc/status/status.pb.o \
	${OBJECTDIR}/gens/src/proto/grpc/testing/control.grpc.pb.o \
	${OBJECTDIR}/gens/src/proto/grpc/testing/control.pb.o \
	${OBJECTDIR}/gens/src/proto/grpc/testing/duplicate/echo_duplicate.grpc.pb.o \
	${OBJECTDIR}/gens/src/proto/grpc/testing/duplicate/echo_duplicate.pb.o \
	${OBJECTDIR}/gens/src/proto/grpc/testing/echo.grpc.pb.o \
	${OBJECTDIR}/gens/src/proto/grpc/testing/echo.pb.o \
	${OBJECTDIR}/gens/src/proto/grpc/testing/echo_messages.grpc.pb.o \
	${OBJECTDIR}/gens/src/proto/grpc/testing/echo_messages.pb.o \
	${OBJECTDIR}/gens/src/proto/grpc/testing/messages.grpc.pb.o \
	${OBJECTDIR}/gens/src/proto/grpc/testing/messages.pb.o \
	${OBJECTDIR}/gens/src/proto/grpc/testing/payloads.grpc.pb.o \
	${OBJECTDIR}/gens/src/proto/grpc/testing/payloads.pb.o \
	${OBJECTDIR}/gens/src/proto/grpc/testing/services.grpc.pb.o \
	${OBJECTDIR}/gens/src/proto/grpc/testing/services.pb.o \
	${OBJECTDIR}/gens/src/proto/grpc/testing/stats.grpc.pb.o \
	${OBJECTDIR}/gens/src/proto/grpc/testing/stats.pb.o \
	${OBJECTDIR}/src/core/ext/census/base_resources.o \
	${OBJECTDIR}/src/core/ext/census/census_init.o \
	${OBJECTDIR}/src/core/ext/census/census_log.o \
	${OBJECTDIR}/src/core/ext/census/census_rpc_stats.o \
	${OBJECTDIR}/src/core/ext/census/census_tracing.o \
	${OBJECTDIR}/src/core/ext/census/context.o \
	${OBJECTDIR}/src/core/ext/census/gen/census.pb.o \
	${OBJECTDIR}/src/core/ext/census/gen/trace_context.pb.o \
	${OBJECTDIR}/src/core/ext/census/grpc_context.o \
	${OBJECTDIR}/src/core/ext/census/grpc_filter.o \
	${OBJECTDIR}/src/core/ext/census/grpc_plugin.o \
	${OBJECTDIR}/src/core/ext/census/hash_table.o \
	${OBJECTDIR}/src/core/ext/census/initialize.o \
	${OBJECTDIR}/src/core/ext/census/intrusive_hash_map.o \
	${OBJECTDIR}/src/core/ext/census/mlog.o \
	${OBJECTDIR}/src/core/ext/census/operation.o \
	${OBJECTDIR}/src/core/ext/census/placeholders.o \
	${OBJECTDIR}/src/core/ext/census/resource.o \
	${OBJECTDIR}/src/core/ext/census/trace_context.o \
	${OBJECTDIR}/src/core/ext/census/tracing.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/channel_connectivity.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/client_channel.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/client_channel_factory.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/client_channel_plugin.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/connector.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/http_connect_handshaker.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/http_proxy.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/grpclb/client_load_reporting_filter.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/grpclb/grpclb.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/grpclb/grpclb_channel.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/grpclb/grpclb_channel_secure.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/grpclb/grpclb_client_stats.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/grpclb/load_balancer_api.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/grpclb/proto/grpc/lb/v1/load_balancer.pb.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/pick_first/pick_first.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/round_robin/round_robin.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy_factory.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy_registry.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/parse_address.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/proxy_mapper.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/proxy_mapper_registry.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/resolver.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/resolver/dns/c_ares/dns_resolver_ares.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/resolver/dns/c_ares/grpc_ares_ev_driver_posix.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/resolver/dns/c_ares/grpc_ares_wrapper.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/resolver/dns/native/dns_resolver.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/resolver/sockaddr/sockaddr_resolver.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/resolver_factory.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/resolver_registry.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/retry_throttle.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/subchannel.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/subchannel_index.o \
	${OBJECTDIR}/src/core/ext/filters/client_channel/uri_parser.o \
	${OBJECTDIR}/src/core/ext/filters/deadline/deadline_filter.o \
	${OBJECTDIR}/src/core/ext/filters/http/client/http_client_filter.o \
	${OBJECTDIR}/src/core/ext/filters/http/http_filters_plugin.o \
	${OBJECTDIR}/src/core/ext/filters/http/message_compress/message_compress_filter.o \
	${OBJECTDIR}/src/core/ext/filters/http/server/http_server_filter.o \
	${OBJECTDIR}/src/core/ext/filters/load_reporting/load_reporting.o \
	${OBJECTDIR}/src/core/ext/filters/load_reporting/load_reporting_filter.o \
	${OBJECTDIR}/src/core/ext/filters/max_age/max_age_filter.o \
	${OBJECTDIR}/src/core/ext/filters/message_size/message_size_filter.o \
	${OBJECTDIR}/src/core/ext/filters/workarounds/workaround_cronet_compression_filter.o \
	${OBJECTDIR}/src/core/ext/filters/workarounds/workaround_utils.o \
	${OBJECTDIR}/src/core/ext/transport/chttp2/alpn/alpn.o \
	${OBJECTDIR}/src/core/ext/transport/chttp2/client/chttp2_connector.o \
	${OBJECTDIR}/src/core/ext/transport/chttp2/client/insecure/channel_create.o \
	${OBJECTDIR}/src/core/ext/transport/chttp2/client/insecure/channel_create_posix.o \
	${OBJECTDIR}/src/core/ext/transport/chttp2/client/secure/secure_channel_create.o \
	${OBJECTDIR}/src/core/ext/transport/chttp2/server/chttp2_server.o \
	${OBJECTDIR}/src/core/ext/transport/chttp2/server/insecure/server_chttp2.o \
	${OBJECTDIR}/src/core/ext/transport/chttp2/server/insecure/server_chttp2_posix.o \
	${OBJECTDIR}/src/core/ext/transport/chttp2/server/secure/server_secure_chttp2.o \
	${OBJECTDIR}/src/core/ext/transport/chttp2/transport/bin_decoder.o \
	${OBJECTDIR}/src/core/ext/transport/chttp2/transport/bin_encoder.o \
	${OBJECTDIR}/src/core/ext/transport/chttp2/transport/chttp2_plugin.o \
	${OBJECTDIR}/src/core/ext/transport/chttp2/transport/chttp2_transport.o \
	${OBJECTDIR}/src/core/ext/transport/chttp2/transport/frame_data.o \
	${OBJECTDIR}/src/core/ext/transport/chttp2/transport/frame_goaway.o \
	${OBJECTDIR}/src/core/ext/transport/chttp2/transport/frame_ping.o \
	${OBJECTDIR}/src/core/ext/transport/chttp2/transport/frame_rst_stream.o \
	${OBJECTDIR}/src/core/ext/transport/chttp2/transport/frame_settings.o \
	${OBJECTDIR}/src/core/ext/transport/chttp2/transport/frame_window_update.o \
	${OBJECTDIR}/src/core/ext/transport/chttp2/transport/hpack_encoder.o \
	${OBJECTDIR}/src/core/ext/transport/chttp2/transport/hpack_parser.o \
	${OBJECTDIR}/src/core/ext/transport/chttp2/transport/hpack_table.o \
	${OBJECTDIR}/src/core/ext/transport/chttp2/transport/http2_settings.o \
	${OBJECTDIR}/src/core/ext/transport/chttp2/transport/huffsyms.o \
	${OBJECTDIR}/src/core/ext/transport/chttp2/transport/incoming_metadata.o \
	${OBJECTDIR}/src/core/ext/transport/chttp2/transport/parsing.o \
	${OBJECTDIR}/src/core/ext/transport/chttp2/transport/stream_lists.o \
	${OBJECTDIR}/src/core/ext/transport/chttp2/transport/stream_map.o \
	${OBJECTDIR}/src/core/ext/transport/chttp2/transport/varint.o \
	${OBJECTDIR}/src/core/ext/transport/chttp2/transport/writing.o \
	${OBJECTDIR}/src/core/ext/transport/cronet/client/secure/cronet_channel_create.o \
	${OBJECTDIR}/src/core/ext/transport/cronet/transport/cronet_api_dummy.o \
	${OBJECTDIR}/src/core/ext/transport/cronet/transport/cronet_transport.o \
	${OBJECTDIR}/src/core/lib/channel/channel_args.o \
	${OBJECTDIR}/src/core/lib/channel/channel_stack.o \
	${OBJECTDIR}/src/core/lib/channel/channel_stack_builder.o \
	${OBJECTDIR}/src/core/lib/channel/connected_channel.o \
	${OBJECTDIR}/src/core/lib/channel/handshaker.o \
	${OBJECTDIR}/src/core/lib/channel/handshaker_factory.o \
	${OBJECTDIR}/src/core/lib/channel/handshaker_registry.o \
	${OBJECTDIR}/src/core/lib/compression/compression.o \
	${OBJECTDIR}/src/core/lib/compression/message_compress.o \
	${OBJECTDIR}/src/core/lib/debug/trace.o \
	${OBJECTDIR}/src/core/lib/http/format_request.o \
	${OBJECTDIR}/src/core/lib/http/httpcli.o \
	${OBJECTDIR}/src/core/lib/http/httpcli_security_connector.o \
	${OBJECTDIR}/src/core/lib/http/parser.o \
	${OBJECTDIR}/src/core/lib/iomgr/closure.o \
	${OBJECTDIR}/src/core/lib/iomgr/combiner.o \
	${OBJECTDIR}/src/core/lib/iomgr/endpoint.o \
	${OBJECTDIR}/src/core/lib/iomgr/endpoint_pair_posix.o \
	${OBJECTDIR}/src/core/lib/iomgr/endpoint_pair_uv.o \
	${OBJECTDIR}/src/core/lib/iomgr/endpoint_pair_windows.o \
	${OBJECTDIR}/src/core/lib/iomgr/error.o \
	${OBJECTDIR}/src/core/lib/iomgr/ev_epoll1_linux.o \
	${OBJECTDIR}/src/core/lib/iomgr/ev_epoll_limited_pollers_linux.o \
	${OBJECTDIR}/src/core/lib/iomgr/ev_epoll_thread_pool_linux.o \
	${OBJECTDIR}/src/core/lib/iomgr/ev_epollex_linux.o \
	${OBJECTDIR}/src/core/lib/iomgr/ev_epollsig_linux.o \
	${OBJECTDIR}/src/core/lib/iomgr/ev_poll_posix.o \
	${OBJECTDIR}/src/core/lib/iomgr/ev_posix.o \
	${OBJECTDIR}/src/core/lib/iomgr/ev_windows.o \
	${OBJECTDIR}/src/core/lib/iomgr/exec_ctx.o \
	${OBJECTDIR}/src/core/lib/iomgr/executor.o \
	${OBJECTDIR}/src/core/lib/iomgr/iocp_windows.o \
	${OBJECTDIR}/src/core/lib/iomgr/iomgr.o \
	${OBJECTDIR}/src/core/lib/iomgr/iomgr_posix.o \
	${OBJECTDIR}/src/core/lib/iomgr/iomgr_uv.o \
	${OBJECTDIR}/src/core/lib/iomgr/iomgr_windows.o \
	${OBJECTDIR}/src/core/lib/iomgr/is_epollexclusive_available.o \
	${OBJECTDIR}/src/core/lib/iomgr/load_file.o \
	${OBJECTDIR}/src/core/lib/iomgr/lockfree_event.o \
	${OBJECTDIR}/src/core/lib/iomgr/network_status_tracker.o \
	${OBJECTDIR}/src/core/lib/iomgr/polling_entity.o \
	${OBJECTDIR}/src/core/lib/iomgr/pollset_set_uv.o \
	${OBJECTDIR}/src/core/lib/iomgr/pollset_set_windows.o \
	${OBJECTDIR}/src/core/lib/iomgr/pollset_uv.o \
	${OBJECTDIR}/src/core/lib/iomgr/pollset_windows.o \
	${OBJECTDIR}/src/core/lib/iomgr/resolve_address_posix.o \
	${OBJECTDIR}/src/core/lib/iomgr/resolve_address_uv.o \
	${OBJECTDIR}/src/core/lib/iomgr/resolve_address_windows.o \
	${OBJECTDIR}/src/core/lib/iomgr/resource_quota.o \
	${OBJECTDIR}/src/core/lib/iomgr/sockaddr_utils.o \
	${OBJECTDIR}/src/core/lib/iomgr/socket_factory_posix.o \
	${OBJECTDIR}/src/core/lib/iomgr/socket_mutator.o \
	${OBJECTDIR}/src/core/lib/iomgr/socket_utils_common_posix.o \
	${OBJECTDIR}/src/core/lib/iomgr/socket_utils_linux.o \
	${OBJECTDIR}/src/core/lib/iomgr/socket_utils_posix.o \
	${OBJECTDIR}/src/core/lib/iomgr/socket_utils_uv.o \
	${OBJECTDIR}/src/core/lib/iomgr/socket_utils_windows.o \
	${OBJECTDIR}/src/core/lib/iomgr/socket_windows.o \
	${OBJECTDIR}/src/core/lib/iomgr/tcp_client_posix.o \
	${OBJECTDIR}/src/core/lib/iomgr/tcp_client_uv.o \
	${OBJECTDIR}/src/core/lib/iomgr/tcp_client_windows.o \
	${OBJECTDIR}/src/core/lib/iomgr/tcp_posix.o \
	${OBJECTDIR}/src/core/lib/iomgr/tcp_server_posix.o \
	${OBJECTDIR}/src/core/lib/iomgr/tcp_server_utils_posix_common.o \
	${OBJECTDIR}/src/core/lib/iomgr/tcp_server_utils_posix_ifaddrs.o \
	${OBJECTDIR}/src/core/lib/iomgr/tcp_server_utils_posix_noifaddrs.o \
	${OBJECTDIR}/src/core/lib/iomgr/tcp_server_uv.o \
	${OBJECTDIR}/src/core/lib/iomgr/tcp_server_windows.o \
	${OBJECTDIR}/src/core/lib/iomgr/tcp_uv.o \
	${OBJECTDIR}/src/core/lib/iomgr/tcp_windows.o \
	${OBJECTDIR}/src/core/lib/iomgr/time_averaged_stats.o \
	${OBJECTDIR}/src/core/lib/iomgr/timer_generic.o \
	${OBJECTDIR}/src/core/lib/iomgr/timer_heap.o \
	${OBJECTDIR}/src/core/lib/iomgr/timer_manager.o \
	${OBJECTDIR}/src/core/lib/iomgr/timer_uv.o \
	${OBJECTDIR}/src/core/lib/iomgr/udp_server.o \
	${OBJECTDIR}/src/core/lib/iomgr/unix_sockets_posix.o \
	${OBJECTDIR}/src/core/lib/iomgr/unix_sockets_posix_noop.o \
	${OBJECTDIR}/src/core/lib/iomgr/wakeup_fd_cv.o \
	${OBJECTDIR}/src/core/lib/iomgr/wakeup_fd_eventfd.o \
	${OBJECTDIR}/src/core/lib/iomgr/wakeup_fd_nospecial.o \
	${OBJECTDIR}/src/core/lib/iomgr/wakeup_fd_pipe.o \
	${OBJECTDIR}/src/core/lib/iomgr/wakeup_fd_posix.o \
	${OBJECTDIR}/src/core/lib/iomgr/workqueue_uv.o \
	${OBJECTDIR}/src/core/lib/iomgr/workqueue_windows.o \
	${OBJECTDIR}/src/core/lib/json/json.o \
	${OBJECTDIR}/src/core/lib/json/json_reader.o \
	${OBJECTDIR}/src/core/lib/json/json_string.o \
	${OBJECTDIR}/src/core/lib/json/json_writer.o \
	${OBJECTDIR}/src/core/lib/profiling/basic_timers.o \
	${OBJECTDIR}/src/core/lib/profiling/stap_timers.o \
	${OBJECTDIR}/src/core/lib/security/context/security_context.o \
	${OBJECTDIR}/src/core/lib/security/credentials/composite/composite_credentials.o \
	${OBJECTDIR}/src/core/lib/security/credentials/credentials.o \
	${OBJECTDIR}/src/core/lib/security/credentials/credentials_metadata.o \
	${OBJECTDIR}/src/core/lib/security/credentials/fake/fake_credentials.o \
	${OBJECTDIR}/src/core/lib/security/credentials/google_default/credentials_generic.o \
	${OBJECTDIR}/src/core/lib/security/credentials/google_default/google_default_credentials.o \
	${OBJECTDIR}/src/core/lib/security/credentials/iam/iam_credentials.o \
	${OBJECTDIR}/src/core/lib/security/credentials/jwt/json_token.o \
	${OBJECTDIR}/src/core/lib/security/credentials/jwt/jwt_credentials.o \
	${OBJECTDIR}/src/core/lib/security/credentials/jwt/jwt_verifier.o \
	${OBJECTDIR}/src/core/lib/security/credentials/oauth2/oauth2_credentials.o \
	${OBJECTDIR}/src/core/lib/security/credentials/plugin/plugin_credentials.o \
	${OBJECTDIR}/src/core/lib/security/credentials/ssl/ssl_credentials.o \
	${OBJECTDIR}/src/core/lib/security/transport/client_auth_filter.o \
	${OBJECTDIR}/src/core/lib/security/transport/lb_targets_info.o \
	${OBJECTDIR}/src/core/lib/security/transport/secure_endpoint.o \
	${OBJECTDIR}/src/core/lib/security/transport/security_connector.o \
	${OBJECTDIR}/src/core/lib/security/transport/security_handshaker.o \
	${OBJECTDIR}/src/core/lib/security/transport/server_auth_filter.o \
	${OBJECTDIR}/src/core/lib/security/transport/tsi_error.o \
	${OBJECTDIR}/src/core/lib/security/util/json_util.o \
	${OBJECTDIR}/src/core/lib/slice/b64.o \
	${OBJECTDIR}/src/core/lib/slice/percent_encoding.o \
	${OBJECTDIR}/src/core/lib/slice/slice.o \
	${OBJECTDIR}/src/core/lib/slice/slice_buffer.o \
	${OBJECTDIR}/src/core/lib/slice/slice_hash_table.o \
	${OBJECTDIR}/src/core/lib/slice/slice_intern.o \
	${OBJECTDIR}/src/core/lib/slice/slice_string_helpers.o \
	${OBJECTDIR}/src/core/lib/support/alloc.o \
	${OBJECTDIR}/src/core/lib/support/arena.o \
	${OBJECTDIR}/src/core/lib/support/atm.o \
	${OBJECTDIR}/src/core/lib/support/avl.o \
	${OBJECTDIR}/src/core/lib/support/backoff.o \
	${OBJECTDIR}/src/core/lib/support/cmdline.o \
	${OBJECTDIR}/src/core/lib/support/cpu_iphone.o \
	${OBJECTDIR}/src/core/lib/support/cpu_linux.o \
	${OBJECTDIR}/src/core/lib/support/cpu_posix.o \
	${OBJECTDIR}/src/core/lib/support/cpu_windows.o \
	${OBJECTDIR}/src/core/lib/support/env_linux.o \
	${OBJECTDIR}/src/core/lib/support/env_posix.o \
	${OBJECTDIR}/src/core/lib/support/env_windows.o \
	${OBJECTDIR}/src/core/lib/support/histogram.o \
	${OBJECTDIR}/src/core/lib/support/host_port.o \
	${OBJECTDIR}/src/core/lib/support/log.o \
	${OBJECTDIR}/src/core/lib/support/log_android.o \
	${OBJECTDIR}/src/core/lib/support/log_linux.o \
	${OBJECTDIR}/src/core/lib/support/log_posix.o \
	${OBJECTDIR}/src/core/lib/support/log_windows.o \
	${OBJECTDIR}/src/core/lib/support/mpscq.o \
	${OBJECTDIR}/src/core/lib/support/murmur_hash.o \
	${OBJECTDIR}/src/core/lib/support/stack_lockfree.o \
	${OBJECTDIR}/src/core/lib/support/string.o \
	${OBJECTDIR}/src/core/lib/support/string_posix.o \
	${OBJECTDIR}/src/core/lib/support/string_util_windows.o \
	${OBJECTDIR}/src/core/lib/support/string_windows.o \
	${OBJECTDIR}/src/core/lib/support/subprocess_posix.o \
	${OBJECTDIR}/src/core/lib/support/subprocess_windows.o \
	${OBJECTDIR}/src/core/lib/support/sync.o \
	${OBJECTDIR}/src/core/lib/support/sync_posix.o \
	${OBJECTDIR}/src/core/lib/support/sync_windows.o \
	${OBJECTDIR}/src/core/lib/support/thd.o \
	${OBJECTDIR}/src/core/lib/support/thd_posix.o \
	${OBJECTDIR}/src/core/lib/support/thd_windows.o \
	${OBJECTDIR}/src/core/lib/support/time.o \
	${OBJECTDIR}/src/core/lib/support/time_posix.o \
	${OBJECTDIR}/src/core/lib/support/time_precise.o \
	${OBJECTDIR}/src/core/lib/support/time_windows.o \
	${OBJECTDIR}/src/core/lib/support/tls_pthread.o \
	${OBJECTDIR}/src/core/lib/support/tmpfile_msys.o \
	${OBJECTDIR}/src/core/lib/support/tmpfile_posix.o \
	${OBJECTDIR}/src/core/lib/support/tmpfile_windows.o \
	${OBJECTDIR}/src/core/lib/support/wrap_memcpy.o \
	${OBJECTDIR}/src/core/lib/surface/alarm.o \
	${OBJECTDIR}/src/core/lib/surface/api_trace.o \
	${OBJECTDIR}/src/core/lib/surface/byte_buffer.o \
	${OBJECTDIR}/src/core/lib/surface/byte_buffer_reader.o \
	${OBJECTDIR}/src/core/lib/surface/call.o \
	${OBJECTDIR}/src/core/lib/surface/call_details.o \
	${OBJECTDIR}/src/core/lib/surface/call_log_batch.o \
	${OBJECTDIR}/src/core/lib/surface/channel.o \
	${OBJECTDIR}/src/core/lib/surface/channel_init.o \
	${OBJECTDIR}/src/core/lib/surface/channel_ping.o \
	${OBJECTDIR}/src/core/lib/surface/channel_stack_type.o \
	${OBJECTDIR}/src/core/lib/surface/completion_queue.o \
	${OBJECTDIR}/src/core/lib/surface/completion_queue_factory.o \
	${OBJECTDIR}/src/core/lib/surface/event_string.o \
	${OBJECTDIR}/src/core/lib/surface/init.o \
	${OBJECTDIR}/src/core/lib/surface/init_secure.o \
	${OBJECTDIR}/src/core/lib/surface/init_unsecure.o \
	${OBJECTDIR}/src/core/lib/surface/lame_client.o \
	${OBJECTDIR}/src/core/lib/surface/metadata_array.o \
	${OBJECTDIR}/src/core/lib/surface/server.o \
	${OBJECTDIR}/src/core/lib/surface/validate_metadata.o \
	${OBJECTDIR}/src/core/lib/surface/version.o \
	${OBJECTDIR}/src/core/lib/transport/bdp_estimator.o \
	${OBJECTDIR}/src/core/lib/transport/byte_stream.o \
	${OBJECTDIR}/src/core/lib/transport/connectivity_state.o \
	${OBJECTDIR}/src/core/lib/transport/error_utils.o \
	${OBJECTDIR}/src/core/lib/transport/metadata.o \
	${OBJECTDIR}/src/core/lib/transport/metadata_batch.o \
	${OBJECTDIR}/src/core/lib/transport/pid_controller.o \
	${OBJECTDIR}/src/core/lib/transport/service_config.o \
	${OBJECTDIR}/src/core/lib/transport/static_metadata.o \
	${OBJECTDIR}/src/core/lib/transport/status_conversion.o \
	${OBJECTDIR}/src/core/lib/transport/timeout_encoding.o \
	${OBJECTDIR}/src/core/lib/transport/transport.o \
	${OBJECTDIR}/src/core/lib/transport/transport_op_string.o \
	${OBJECTDIR}/src/core/plugin_registry/grpc_plugin_registry.o \
	${OBJECTDIR}/src/core/tsi/fake_transport_security.o \
	${OBJECTDIR}/src/core/tsi/ssl_transport_security.o \
	${OBJECTDIR}/src/core/tsi/transport_security.o \
	${OBJECTDIR}/src/core/tsi/transport_security_adapter.o \
	${OBJECTDIR}/src/cpp/client/channel_cc.o \
	${OBJECTDIR}/src/cpp/client/client_context.o \
	${OBJECTDIR}/src/cpp/client/create_channel.o \
	${OBJECTDIR}/src/cpp/client/create_channel_internal.o \
	${OBJECTDIR}/src/cpp/client/create_channel_posix.o \
	${OBJECTDIR}/src/cpp/client/credentials_cc.o \
	${OBJECTDIR}/src/cpp/client/cronet_credentials.o \
	${OBJECTDIR}/src/cpp/client/generic_stub.o \
	${OBJECTDIR}/src/cpp/client/insecure_credentials.o \
	${OBJECTDIR}/src/cpp/client/secure_credentials.o \
	${OBJECTDIR}/src/cpp/codegen/codegen_init.o \
	${OBJECTDIR}/src/cpp/common/auth_property_iterator.o \
	${OBJECTDIR}/src/cpp/common/channel_arguments.o \
	${OBJECTDIR}/src/cpp/common/channel_filter.o \
	${OBJECTDIR}/src/cpp/common/completion_queue_cc.o \
	${OBJECTDIR}/src/cpp/common/core_codegen.o \
	${OBJECTDIR}/src/cpp/common/insecure_create_auth_context.o \
	${OBJECTDIR}/src/cpp/common/resource_quota_cc.o \
	${OBJECTDIR}/src/cpp/common/rpc_method.o \
	${OBJECTDIR}/src/cpp/common/secure_auth_context.o \
	${OBJECTDIR}/src/cpp/common/secure_channel_arguments.o \
	${OBJECTDIR}/src/cpp/common/secure_create_auth_context.o \
	${OBJECTDIR}/src/cpp/common/version_cc.o \
	${OBJECTDIR}/src/cpp/ext/proto_server_reflection.o \
	${OBJECTDIR}/src/cpp/ext/proto_server_reflection_plugin.o \
	${OBJECTDIR}/src/cpp/server/async_generic_service.o \
	${OBJECTDIR}/src/cpp/server/channel_argument_option.o \
	${OBJECTDIR}/src/cpp/server/create_default_thread_pool.o \
	${OBJECTDIR}/src/cpp/server/dynamic_thread_pool.o \
	${OBJECTDIR}/src/cpp/server/health/default_health_check_service.o \
	${OBJECTDIR}/src/cpp/server/health/health.pb.o \
	${OBJECTDIR}/src/cpp/server/health/health_check_service.o \
	${OBJECTDIR}/src/cpp/server/health/health_check_service_server_builder_option.o \
	${OBJECTDIR}/src/cpp/server/insecure_server_credentials.o \
	${OBJECTDIR}/src/cpp/server/secure_server_credentials.o \
	${OBJECTDIR}/src/cpp/server/server_builder.o \
	${OBJECTDIR}/src/cpp/server/server_cc.o \
	${OBJECTDIR}/src/cpp/server/server_context.o \
	${OBJECTDIR}/src/cpp/server/server_credentials.o \
	${OBJECTDIR}/src/cpp/server/server_posix.o \
	${OBJECTDIR}/src/cpp/thread_manager/thread_manager.o \
	${OBJECTDIR}/src/cpp/util/byte_buffer_cc.o \
	${OBJECTDIR}/src/cpp/util/error_details.o \
	${OBJECTDIR}/src/cpp/util/slice_cc.o \
	${OBJECTDIR}/src/cpp/util/status.o \
	${OBJECTDIR}/src/cpp/util/string_ref.o \
	${OBJECTDIR}/src/cpp/util/time_cc.o \
	${OBJECTDIR}/third_party/cares/cares/ares__close_sockets.o \
	${OBJECTDIR}/third_party/cares/cares/ares__get_hostent.o \
	${OBJECTDIR}/third_party/cares/cares/ares__read_line.o \
	${OBJECTDIR}/third_party/cares/cares/ares__timeval.o \
	${OBJECTDIR}/third_party/cares/cares/ares_cancel.o \
	${OBJECTDIR}/third_party/cares/cares/ares_create_query.o \
	${OBJECTDIR}/third_party/cares/cares/ares_data.o \
	${OBJECTDIR}/third_party/cares/cares/ares_destroy.o \
	${OBJECTDIR}/third_party/cares/cares/ares_expand_name.o \
	${OBJECTDIR}/third_party/cares/cares/ares_expand_string.o \
	${OBJECTDIR}/third_party/cares/cares/ares_fds.o \
	${OBJECTDIR}/third_party/cares/cares/ares_free_hostent.o \
	${OBJECTDIR}/third_party/cares/cares/ares_free_string.o \
	${OBJECTDIR}/third_party/cares/cares/ares_getenv.o \
	${OBJECTDIR}/third_party/cares/cares/ares_gethostbyaddr.o \
	${OBJECTDIR}/third_party/cares/cares/ares_gethostbyname.o \
	${OBJECTDIR}/third_party/cares/cares/ares_getnameinfo.o \
	${OBJECTDIR}/third_party/cares/cares/ares_getopt.o \
	${OBJECTDIR}/third_party/cares/cares/ares_getsock.o \
	${OBJECTDIR}/third_party/cares/cares/ares_init.o \
	${OBJECTDIR}/third_party/cares/cares/ares_library_init.o \
	${OBJECTDIR}/third_party/cares/cares/ares_llist.o \
	${OBJECTDIR}/third_party/cares/cares/ares_mkquery.o \
	${OBJECTDIR}/third_party/cares/cares/ares_nowarn.o \
	${OBJECTDIR}/third_party/cares/cares/ares_options.o \
	${OBJECTDIR}/third_party/cares/cares/ares_parse_a_reply.o \
	${OBJECTDIR}/third_party/cares/cares/ares_parse_aaaa_reply.o \
	${OBJECTDIR}/third_party/cares/cares/ares_parse_mx_reply.o \
	${OBJECTDIR}/third_party/cares/cares/ares_parse_naptr_reply.o \
	${OBJECTDIR}/third_party/cares/cares/ares_parse_ns_reply.o \
	${OBJECTDIR}/third_party/cares/cares/ares_parse_ptr_reply.o \
	${OBJECTDIR}/third_party/cares/cares/ares_parse_soa_reply.o \
	${OBJECTDIR}/third_party/cares/cares/ares_parse_srv_reply.o \
	${OBJECTDIR}/third_party/cares/cares/ares_parse_txt_reply.o \
	${OBJECTDIR}/third_party/cares/cares/ares_platform.o \
	${OBJECTDIR}/third_party/cares/cares/ares_process.o \
	${OBJECTDIR}/third_party/cares/cares/ares_query.o \
	${OBJECTDIR}/third_party/cares/cares/ares_search.o \
	${OBJECTDIR}/third_party/cares/cares/ares_send.o \
	${OBJECTDIR}/third_party/cares/cares/ares_strcasecmp.o \
	${OBJECTDIR}/third_party/cares/cares/ares_strdup.o \
	${OBJECTDIR}/third_party/cares/cares/ares_strerror.o \
	${OBJECTDIR}/third_party/cares/cares/ares_timeout.o \
	${OBJECTDIR}/third_party/cares/cares/ares_version.o \
	${OBJECTDIR}/third_party/cares/cares/ares_writev.o \
	${OBJECTDIR}/third_party/cares/cares/bitncmp.o \
	${OBJECTDIR}/third_party/cares/cares/inet_net_pton.o \
	${OBJECTDIR}/third_party/cares/cares/inet_ntop.o \
	${OBJECTDIR}/third_party/cares/cares/windows_port.o \
	${OBJECTDIR}/third_party/nanopb/pb_common.o \
	${OBJECTDIR}/third_party/nanopb/pb_decode.o \
	${OBJECTDIR}/third_party/nanopb/pb_encode.o \
	${OBJECTDIR}/third_party/zlib/adler32.o \
	${OBJECTDIR}/third_party/zlib/compress.o \
	${OBJECTDIR}/third_party/zlib/crc32.o \
	${OBJECTDIR}/third_party/zlib/deflate.o \
	${OBJECTDIR}/third_party/zlib/gzclose.o \
	${OBJECTDIR}/third_party/zlib/gzlib.o \
	${OBJECTDIR}/third_party/zlib/gzread.o \
	${OBJECTDIR}/third_party/zlib/gzwrite.o \
	${OBJECTDIR}/third_party/zlib/infback.o \
	${OBJECTDIR}/third_party/zlib/inffast.o \
	${OBJECTDIR}/third_party/zlib/inflate.o \
	${OBJECTDIR}/third_party/zlib/inftrees.o \
	${OBJECTDIR}/third_party/zlib/trees.o \
	${OBJECTDIR}/third_party/zlib/uncompr.o \
	${OBJECTDIR}/third_party/zlib/zutil.o


# C Compiler Flags
CFLAGS=

# CC Compiler Flags
CCFLAGS=
CXXFLAGS=

# Fortran Compiler Flags
FFLAGS=

# Assembler Flags
ASFLAGS=

# Link Libraries and Options
LDLIBSOPTIONS=

# Build Targets
.build-conf: ${BUILD_SUBPROJECTS}
	"${MAKE}"  -f nbproject/Makefile-${CND_CONF}.mk lib/libgrpcalld.a

lib/libgrpcalld.a: ${OBJECTFILES}
	${MKDIR} -p lib
	${RM} lib/libgrpcalld.a
	${AR} -rv lib/libgrpcalld.a ${OBJECTFILES} 
	$(RANLIB) lib/libgrpcalld.a

${OBJECTDIR}/gens/src/proto/grpc/health/v1/health.grpc.pb.o: gens/src/proto/grpc/health/v1/health.grpc.pb.cc
	${MKDIR} -p ${OBJECTDIR}/gens/src/proto/grpc/health/v1
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/gens/src/proto/grpc/health/v1/health.grpc.pb.o gens/src/proto/grpc/health/v1/health.grpc.pb.cc

${OBJECTDIR}/gens/src/proto/grpc/health/v1/health.pb.o: gens/src/proto/grpc/health/v1/health.pb.cc
	${MKDIR} -p ${OBJECTDIR}/gens/src/proto/grpc/health/v1
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/gens/src/proto/grpc/health/v1/health.pb.o gens/src/proto/grpc/health/v1/health.pb.cc

${OBJECTDIR}/gens/src/proto/grpc/reflection/v1alpha/reflection.grpc.pb.o: gens/src/proto/grpc/reflection/v1alpha/reflection.grpc.pb.cc
	${MKDIR} -p ${OBJECTDIR}/gens/src/proto/grpc/reflection/v1alpha
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/gens/src/proto/grpc/reflection/v1alpha/reflection.grpc.pb.o gens/src/proto/grpc/reflection/v1alpha/reflection.grpc.pb.cc

${OBJECTDIR}/gens/src/proto/grpc/reflection/v1alpha/reflection.pb.o: gens/src/proto/grpc/reflection/v1alpha/reflection.pb.cc
	${MKDIR} -p ${OBJECTDIR}/gens/src/proto/grpc/reflection/v1alpha
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/gens/src/proto/grpc/reflection/v1alpha/reflection.pb.o gens/src/proto/grpc/reflection/v1alpha/reflection.pb.cc

${OBJECTDIR}/gens/src/proto/grpc/status/status.grpc.pb.o: gens/src/proto/grpc/status/status.grpc.pb.cc
	${MKDIR} -p ${OBJECTDIR}/gens/src/proto/grpc/status
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/gens/src/proto/grpc/status/status.grpc.pb.o gens/src/proto/grpc/status/status.grpc.pb.cc

${OBJECTDIR}/gens/src/proto/grpc/status/status.pb.o: gens/src/proto/grpc/status/status.pb.cc
	${MKDIR} -p ${OBJECTDIR}/gens/src/proto/grpc/status
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/gens/src/proto/grpc/status/status.pb.o gens/src/proto/grpc/status/status.pb.cc

${OBJECTDIR}/gens/src/proto/grpc/testing/control.grpc.pb.o: gens/src/proto/grpc/testing/control.grpc.pb.cc
	${MKDIR} -p ${OBJECTDIR}/gens/src/proto/grpc/testing
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/gens/src/proto/grpc/testing/control.grpc.pb.o gens/src/proto/grpc/testing/control.grpc.pb.cc

${OBJECTDIR}/gens/src/proto/grpc/testing/control.pb.o: gens/src/proto/grpc/testing/control.pb.cc
	${MKDIR} -p ${OBJECTDIR}/gens/src/proto/grpc/testing
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/gens/src/proto/grpc/testing/control.pb.o gens/src/proto/grpc/testing/control.pb.cc

${OBJECTDIR}/gens/src/proto/grpc/testing/duplicate/echo_duplicate.grpc.pb.o: gens/src/proto/grpc/testing/duplicate/echo_duplicate.grpc.pb.cc
	${MKDIR} -p ${OBJECTDIR}/gens/src/proto/grpc/testing/duplicate
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/gens/src/proto/grpc/testing/duplicate/echo_duplicate.grpc.pb.o gens/src/proto/grpc/testing/duplicate/echo_duplicate.grpc.pb.cc

${OBJECTDIR}/gens/src/proto/grpc/testing/duplicate/echo_duplicate.pb.o: gens/src/proto/grpc/testing/duplicate/echo_duplicate.pb.cc
	${MKDIR} -p ${OBJECTDIR}/gens/src/proto/grpc/testing/duplicate
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/gens/src/proto/grpc/testing/duplicate/echo_duplicate.pb.o gens/src/proto/grpc/testing/duplicate/echo_duplicate.pb.cc

${OBJECTDIR}/gens/src/proto/grpc/testing/echo.grpc.pb.o: gens/src/proto/grpc/testing/echo.grpc.pb.cc
	${MKDIR} -p ${OBJECTDIR}/gens/src/proto/grpc/testing
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/gens/src/proto/grpc/testing/echo.grpc.pb.o gens/src/proto/grpc/testing/echo.grpc.pb.cc

${OBJECTDIR}/gens/src/proto/grpc/testing/echo.pb.o: gens/src/proto/grpc/testing/echo.pb.cc
	${MKDIR} -p ${OBJECTDIR}/gens/src/proto/grpc/testing
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/gens/src/proto/grpc/testing/echo.pb.o gens/src/proto/grpc/testing/echo.pb.cc

${OBJECTDIR}/gens/src/proto/grpc/testing/echo_messages.grpc.pb.o: gens/src/proto/grpc/testing/echo_messages.grpc.pb.cc
	${MKDIR} -p ${OBJECTDIR}/gens/src/proto/grpc/testing
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/gens/src/proto/grpc/testing/echo_messages.grpc.pb.o gens/src/proto/grpc/testing/echo_messages.grpc.pb.cc

${OBJECTDIR}/gens/src/proto/grpc/testing/echo_messages.pb.o: gens/src/proto/grpc/testing/echo_messages.pb.cc
	${MKDIR} -p ${OBJECTDIR}/gens/src/proto/grpc/testing
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/gens/src/proto/grpc/testing/echo_messages.pb.o gens/src/proto/grpc/testing/echo_messages.pb.cc

${OBJECTDIR}/gens/src/proto/grpc/testing/messages.grpc.pb.o: gens/src/proto/grpc/testing/messages.grpc.pb.cc
	${MKDIR} -p ${OBJECTDIR}/gens/src/proto/grpc/testing
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/gens/src/proto/grpc/testing/messages.grpc.pb.o gens/src/proto/grpc/testing/messages.grpc.pb.cc

${OBJECTDIR}/gens/src/proto/grpc/testing/messages.pb.o: gens/src/proto/grpc/testing/messages.pb.cc
	${MKDIR} -p ${OBJECTDIR}/gens/src/proto/grpc/testing
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/gens/src/proto/grpc/testing/messages.pb.o gens/src/proto/grpc/testing/messages.pb.cc

${OBJECTDIR}/gens/src/proto/grpc/testing/payloads.grpc.pb.o: gens/src/proto/grpc/testing/payloads.grpc.pb.cc
	${MKDIR} -p ${OBJECTDIR}/gens/src/proto/grpc/testing
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/gens/src/proto/grpc/testing/payloads.grpc.pb.o gens/src/proto/grpc/testing/payloads.grpc.pb.cc

${OBJECTDIR}/gens/src/proto/grpc/testing/payloads.pb.o: gens/src/proto/grpc/testing/payloads.pb.cc
	${MKDIR} -p ${OBJECTDIR}/gens/src/proto/grpc/testing
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/gens/src/proto/grpc/testing/payloads.pb.o gens/src/proto/grpc/testing/payloads.pb.cc

${OBJECTDIR}/gens/src/proto/grpc/testing/services.grpc.pb.o: gens/src/proto/grpc/testing/services.grpc.pb.cc
	${MKDIR} -p ${OBJECTDIR}/gens/src/proto/grpc/testing
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/gens/src/proto/grpc/testing/services.grpc.pb.o gens/src/proto/grpc/testing/services.grpc.pb.cc

${OBJECTDIR}/gens/src/proto/grpc/testing/services.pb.o: gens/src/proto/grpc/testing/services.pb.cc
	${MKDIR} -p ${OBJECTDIR}/gens/src/proto/grpc/testing
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/gens/src/proto/grpc/testing/services.pb.o gens/src/proto/grpc/testing/services.pb.cc

${OBJECTDIR}/gens/src/proto/grpc/testing/stats.grpc.pb.o: gens/src/proto/grpc/testing/stats.grpc.pb.cc
	${MKDIR} -p ${OBJECTDIR}/gens/src/proto/grpc/testing
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/gens/src/proto/grpc/testing/stats.grpc.pb.o gens/src/proto/grpc/testing/stats.grpc.pb.cc

${OBJECTDIR}/gens/src/proto/grpc/testing/stats.pb.o: gens/src/proto/grpc/testing/stats.pb.cc
	${MKDIR} -p ${OBJECTDIR}/gens/src/proto/grpc/testing
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/gens/src/proto/grpc/testing/stats.pb.o gens/src/proto/grpc/testing/stats.pb.cc

${OBJECTDIR}/src/core/ext/census/base_resources.o: src/core/ext/census/base_resources.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/census
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/census/base_resources.o src/core/ext/census/base_resources.c

${OBJECTDIR}/src/core/ext/census/census_init.o: src/core/ext/census/census_init.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/census
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/census/census_init.o src/core/ext/census/census_init.c

${OBJECTDIR}/src/core/ext/census/census_log.o: src/core/ext/census/census_log.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/census
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/census/census_log.o src/core/ext/census/census_log.c

${OBJECTDIR}/src/core/ext/census/census_rpc_stats.o: src/core/ext/census/census_rpc_stats.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/census
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/census/census_rpc_stats.o src/core/ext/census/census_rpc_stats.c

${OBJECTDIR}/src/core/ext/census/census_tracing.o: src/core/ext/census/census_tracing.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/census
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/census/census_tracing.o src/core/ext/census/census_tracing.c

${OBJECTDIR}/src/core/ext/census/context.o: src/core/ext/census/context.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/census
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/census/context.o src/core/ext/census/context.c

${OBJECTDIR}/src/core/ext/census/gen/census.pb.o: src/core/ext/census/gen/census.pb.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/census/gen
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/census/gen/census.pb.o src/core/ext/census/gen/census.pb.c

${OBJECTDIR}/src/core/ext/census/gen/trace_context.pb.o: src/core/ext/census/gen/trace_context.pb.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/census/gen
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/census/gen/trace_context.pb.o src/core/ext/census/gen/trace_context.pb.c

${OBJECTDIR}/src/core/ext/census/grpc_context.o: src/core/ext/census/grpc_context.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/census
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/census/grpc_context.o src/core/ext/census/grpc_context.c

${OBJECTDIR}/src/core/ext/census/grpc_filter.o: src/core/ext/census/grpc_filter.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/census
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/census/grpc_filter.o src/core/ext/census/grpc_filter.c

${OBJECTDIR}/src/core/ext/census/grpc_plugin.o: src/core/ext/census/grpc_plugin.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/census
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/census/grpc_plugin.o src/core/ext/census/grpc_plugin.c

${OBJECTDIR}/src/core/ext/census/hash_table.o: src/core/ext/census/hash_table.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/census
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/census/hash_table.o src/core/ext/census/hash_table.c

${OBJECTDIR}/src/core/ext/census/initialize.o: src/core/ext/census/initialize.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/census
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/census/initialize.o src/core/ext/census/initialize.c

${OBJECTDIR}/src/core/ext/census/intrusive_hash_map.o: src/core/ext/census/intrusive_hash_map.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/census
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/census/intrusive_hash_map.o src/core/ext/census/intrusive_hash_map.c

${OBJECTDIR}/src/core/ext/census/mlog.o: src/core/ext/census/mlog.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/census
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/census/mlog.o src/core/ext/census/mlog.c

${OBJECTDIR}/src/core/ext/census/operation.o: src/core/ext/census/operation.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/census
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/census/operation.o src/core/ext/census/operation.c

${OBJECTDIR}/src/core/ext/census/placeholders.o: src/core/ext/census/placeholders.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/census
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/census/placeholders.o src/core/ext/census/placeholders.c

${OBJECTDIR}/src/core/ext/census/resource.o: src/core/ext/census/resource.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/census
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/census/resource.o src/core/ext/census/resource.c

${OBJECTDIR}/src/core/ext/census/trace_context.o: src/core/ext/census/trace_context.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/census
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/census/trace_context.o src/core/ext/census/trace_context.c

${OBJECTDIR}/src/core/ext/census/tracing.o: src/core/ext/census/tracing.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/census
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/census/tracing.o src/core/ext/census/tracing.c

${OBJECTDIR}/src/core/ext/filters/client_channel/channel_connectivity.o: src/core/ext/filters/client_channel/channel_connectivity.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/channel_connectivity.o src/core/ext/filters/client_channel/channel_connectivity.c

${OBJECTDIR}/src/core/ext/filters/client_channel/client_channel.o: src/core/ext/filters/client_channel/client_channel.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/client_channel.o src/core/ext/filters/client_channel/client_channel.c

${OBJECTDIR}/src/core/ext/filters/client_channel/client_channel_factory.o: src/core/ext/filters/client_channel/client_channel_factory.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/client_channel_factory.o src/core/ext/filters/client_channel/client_channel_factory.c

${OBJECTDIR}/src/core/ext/filters/client_channel/client_channel_plugin.o: src/core/ext/filters/client_channel/client_channel_plugin.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/client_channel_plugin.o src/core/ext/filters/client_channel/client_channel_plugin.c

${OBJECTDIR}/src/core/ext/filters/client_channel/connector.o: src/core/ext/filters/client_channel/connector.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/connector.o src/core/ext/filters/client_channel/connector.c

${OBJECTDIR}/src/core/ext/filters/client_channel/http_connect_handshaker.o: src/core/ext/filters/client_channel/http_connect_handshaker.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/http_connect_handshaker.o src/core/ext/filters/client_channel/http_connect_handshaker.c

${OBJECTDIR}/src/core/ext/filters/client_channel/http_proxy.o: src/core/ext/filters/client_channel/http_proxy.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/http_proxy.o src/core/ext/filters/client_channel/http_proxy.c

${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy.o: src/core/ext/filters/client_channel/lb_policy.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy.o src/core/ext/filters/client_channel/lb_policy.c

${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/grpclb/client_load_reporting_filter.o: src/core/ext/filters/client_channel/lb_policy/grpclb/client_load_reporting_filter.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/grpclb
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/grpclb/client_load_reporting_filter.o src/core/ext/filters/client_channel/lb_policy/grpclb/client_load_reporting_filter.c

${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/grpclb/grpclb.o: src/core/ext/filters/client_channel/lb_policy/grpclb/grpclb.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/grpclb
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/grpclb/grpclb.o src/core/ext/filters/client_channel/lb_policy/grpclb/grpclb.c

${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/grpclb/grpclb_channel.o: src/core/ext/filters/client_channel/lb_policy/grpclb/grpclb_channel.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/grpclb
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/grpclb/grpclb_channel.o src/core/ext/filters/client_channel/lb_policy/grpclb/grpclb_channel.c

${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/grpclb/grpclb_channel_secure.o: src/core/ext/filters/client_channel/lb_policy/grpclb/grpclb_channel_secure.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/grpclb
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/grpclb/grpclb_channel_secure.o src/core/ext/filters/client_channel/lb_policy/grpclb/grpclb_channel_secure.c

${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/grpclb/grpclb_client_stats.o: src/core/ext/filters/client_channel/lb_policy/grpclb/grpclb_client_stats.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/grpclb
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/grpclb/grpclb_client_stats.o src/core/ext/filters/client_channel/lb_policy/grpclb/grpclb_client_stats.c

${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/grpclb/load_balancer_api.o: src/core/ext/filters/client_channel/lb_policy/grpclb/load_balancer_api.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/grpclb
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/grpclb/load_balancer_api.o src/core/ext/filters/client_channel/lb_policy/grpclb/load_balancer_api.c

${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/grpclb/proto/grpc/lb/v1/load_balancer.pb.o: src/core/ext/filters/client_channel/lb_policy/grpclb/proto/grpc/lb/v1/load_balancer.pb.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/grpclb/proto/grpc/lb/v1
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/grpclb/proto/grpc/lb/v1/load_balancer.pb.o src/core/ext/filters/client_channel/lb_policy/grpclb/proto/grpc/lb/v1/load_balancer.pb.c

${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/pick_first/pick_first.o: src/core/ext/filters/client_channel/lb_policy/pick_first/pick_first.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/pick_first
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/pick_first/pick_first.o src/core/ext/filters/client_channel/lb_policy/pick_first/pick_first.c

${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/round_robin/round_robin.o: src/core/ext/filters/client_channel/lb_policy/round_robin/round_robin.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/round_robin
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy/round_robin/round_robin.o src/core/ext/filters/client_channel/lb_policy/round_robin/round_robin.c

${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy_factory.o: src/core/ext/filters/client_channel/lb_policy_factory.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy_factory.o src/core/ext/filters/client_channel/lb_policy_factory.c

${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy_registry.o: src/core/ext/filters/client_channel/lb_policy_registry.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/lb_policy_registry.o src/core/ext/filters/client_channel/lb_policy_registry.c

${OBJECTDIR}/src/core/ext/filters/client_channel/parse_address.o: src/core/ext/filters/client_channel/parse_address.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/parse_address.o src/core/ext/filters/client_channel/parse_address.c

${OBJECTDIR}/src/core/ext/filters/client_channel/proxy_mapper.o: src/core/ext/filters/client_channel/proxy_mapper.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/proxy_mapper.o src/core/ext/filters/client_channel/proxy_mapper.c

${OBJECTDIR}/src/core/ext/filters/client_channel/proxy_mapper_registry.o: src/core/ext/filters/client_channel/proxy_mapper_registry.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/proxy_mapper_registry.o src/core/ext/filters/client_channel/proxy_mapper_registry.c

${OBJECTDIR}/src/core/ext/filters/client_channel/resolver.o: src/core/ext/filters/client_channel/resolver.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/resolver.o src/core/ext/filters/client_channel/resolver.c

${OBJECTDIR}/src/core/ext/filters/client_channel/resolver/dns/c_ares/dns_resolver_ares.o: src/core/ext/filters/client_channel/resolver/dns/c_ares/dns_resolver_ares.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel/resolver/dns/c_ares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/resolver/dns/c_ares/dns_resolver_ares.o src/core/ext/filters/client_channel/resolver/dns/c_ares/dns_resolver_ares.c

${OBJECTDIR}/src/core/ext/filters/client_channel/resolver/dns/c_ares/grpc_ares_ev_driver_posix.o: src/core/ext/filters/client_channel/resolver/dns/c_ares/grpc_ares_ev_driver_posix.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel/resolver/dns/c_ares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/resolver/dns/c_ares/grpc_ares_ev_driver_posix.o src/core/ext/filters/client_channel/resolver/dns/c_ares/grpc_ares_ev_driver_posix.c

${OBJECTDIR}/src/core/ext/filters/client_channel/resolver/dns/c_ares/grpc_ares_wrapper.o: src/core/ext/filters/client_channel/resolver/dns/c_ares/grpc_ares_wrapper.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel/resolver/dns/c_ares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/resolver/dns/c_ares/grpc_ares_wrapper.o src/core/ext/filters/client_channel/resolver/dns/c_ares/grpc_ares_wrapper.c

${OBJECTDIR}/src/core/ext/filters/client_channel/resolver/dns/native/dns_resolver.o: src/core/ext/filters/client_channel/resolver/dns/native/dns_resolver.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel/resolver/dns/native
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/resolver/dns/native/dns_resolver.o src/core/ext/filters/client_channel/resolver/dns/native/dns_resolver.c

${OBJECTDIR}/src/core/ext/filters/client_channel/resolver/sockaddr/sockaddr_resolver.o: src/core/ext/filters/client_channel/resolver/sockaddr/sockaddr_resolver.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel/resolver/sockaddr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/resolver/sockaddr/sockaddr_resolver.o src/core/ext/filters/client_channel/resolver/sockaddr/sockaddr_resolver.c

${OBJECTDIR}/src/core/ext/filters/client_channel/resolver_factory.o: src/core/ext/filters/client_channel/resolver_factory.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/resolver_factory.o src/core/ext/filters/client_channel/resolver_factory.c

${OBJECTDIR}/src/core/ext/filters/client_channel/resolver_registry.o: src/core/ext/filters/client_channel/resolver_registry.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/resolver_registry.o src/core/ext/filters/client_channel/resolver_registry.c

${OBJECTDIR}/src/core/ext/filters/client_channel/retry_throttle.o: src/core/ext/filters/client_channel/retry_throttle.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/retry_throttle.o src/core/ext/filters/client_channel/retry_throttle.c

${OBJECTDIR}/src/core/ext/filters/client_channel/subchannel.o: src/core/ext/filters/client_channel/subchannel.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/subchannel.o src/core/ext/filters/client_channel/subchannel.c

${OBJECTDIR}/src/core/ext/filters/client_channel/subchannel_index.o: src/core/ext/filters/client_channel/subchannel_index.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/subchannel_index.o src/core/ext/filters/client_channel/subchannel_index.c

${OBJECTDIR}/src/core/ext/filters/client_channel/uri_parser.o: src/core/ext/filters/client_channel/uri_parser.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/client_channel
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/client_channel/uri_parser.o src/core/ext/filters/client_channel/uri_parser.c

${OBJECTDIR}/src/core/ext/filters/deadline/deadline_filter.o: src/core/ext/filters/deadline/deadline_filter.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/deadline
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/deadline/deadline_filter.o src/core/ext/filters/deadline/deadline_filter.c

${OBJECTDIR}/src/core/ext/filters/http/client/http_client_filter.o: src/core/ext/filters/http/client/http_client_filter.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/http/client
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/http/client/http_client_filter.o src/core/ext/filters/http/client/http_client_filter.c

${OBJECTDIR}/src/core/ext/filters/http/http_filters_plugin.o: src/core/ext/filters/http/http_filters_plugin.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/http
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/http/http_filters_plugin.o src/core/ext/filters/http/http_filters_plugin.c

${OBJECTDIR}/src/core/ext/filters/http/message_compress/message_compress_filter.o: src/core/ext/filters/http/message_compress/message_compress_filter.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/http/message_compress
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/http/message_compress/message_compress_filter.o src/core/ext/filters/http/message_compress/message_compress_filter.c

${OBJECTDIR}/src/core/ext/filters/http/server/http_server_filter.o: src/core/ext/filters/http/server/http_server_filter.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/http/server
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/http/server/http_server_filter.o src/core/ext/filters/http/server/http_server_filter.c

${OBJECTDIR}/src/core/ext/filters/load_reporting/load_reporting.o: src/core/ext/filters/load_reporting/load_reporting.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/load_reporting
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/load_reporting/load_reporting.o src/core/ext/filters/load_reporting/load_reporting.c

${OBJECTDIR}/src/core/ext/filters/load_reporting/load_reporting_filter.o: src/core/ext/filters/load_reporting/load_reporting_filter.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/load_reporting
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/load_reporting/load_reporting_filter.o src/core/ext/filters/load_reporting/load_reporting_filter.c

${OBJECTDIR}/src/core/ext/filters/max_age/max_age_filter.o: src/core/ext/filters/max_age/max_age_filter.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/max_age
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/max_age/max_age_filter.o src/core/ext/filters/max_age/max_age_filter.c

${OBJECTDIR}/src/core/ext/filters/message_size/message_size_filter.o: src/core/ext/filters/message_size/message_size_filter.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/message_size
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/message_size/message_size_filter.o src/core/ext/filters/message_size/message_size_filter.c

${OBJECTDIR}/src/core/ext/filters/workarounds/workaround_cronet_compression_filter.o: src/core/ext/filters/workarounds/workaround_cronet_compression_filter.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/workarounds
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/workarounds/workaround_cronet_compression_filter.o src/core/ext/filters/workarounds/workaround_cronet_compression_filter.c

${OBJECTDIR}/src/core/ext/filters/workarounds/workaround_utils.o: src/core/ext/filters/workarounds/workaround_utils.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/filters/workarounds
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/filters/workarounds/workaround_utils.o src/core/ext/filters/workarounds/workaround_utils.c

${OBJECTDIR}/src/core/ext/transport/chttp2/alpn/alpn.o: src/core/ext/transport/chttp2/alpn/alpn.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/transport/chttp2/alpn
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/transport/chttp2/alpn/alpn.o src/core/ext/transport/chttp2/alpn/alpn.c

${OBJECTDIR}/src/core/ext/transport/chttp2/client/chttp2_connector.o: src/core/ext/transport/chttp2/client/chttp2_connector.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/transport/chttp2/client
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/transport/chttp2/client/chttp2_connector.o src/core/ext/transport/chttp2/client/chttp2_connector.c

${OBJECTDIR}/src/core/ext/transport/chttp2/client/insecure/channel_create.o: src/core/ext/transport/chttp2/client/insecure/channel_create.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/transport/chttp2/client/insecure
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/transport/chttp2/client/insecure/channel_create.o src/core/ext/transport/chttp2/client/insecure/channel_create.c

${OBJECTDIR}/src/core/ext/transport/chttp2/client/insecure/channel_create_posix.o: src/core/ext/transport/chttp2/client/insecure/channel_create_posix.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/transport/chttp2/client/insecure
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/transport/chttp2/client/insecure/channel_create_posix.o src/core/ext/transport/chttp2/client/insecure/channel_create_posix.c

${OBJECTDIR}/src/core/ext/transport/chttp2/client/secure/secure_channel_create.o: src/core/ext/transport/chttp2/client/secure/secure_channel_create.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/transport/chttp2/client/secure
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/transport/chttp2/client/secure/secure_channel_create.o src/core/ext/transport/chttp2/client/secure/secure_channel_create.c

${OBJECTDIR}/src/core/ext/transport/chttp2/server/chttp2_server.o: src/core/ext/transport/chttp2/server/chttp2_server.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/transport/chttp2/server
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/transport/chttp2/server/chttp2_server.o src/core/ext/transport/chttp2/server/chttp2_server.c

${OBJECTDIR}/src/core/ext/transport/chttp2/server/insecure/server_chttp2.o: src/core/ext/transport/chttp2/server/insecure/server_chttp2.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/transport/chttp2/server/insecure
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/transport/chttp2/server/insecure/server_chttp2.o src/core/ext/transport/chttp2/server/insecure/server_chttp2.c

${OBJECTDIR}/src/core/ext/transport/chttp2/server/insecure/server_chttp2_posix.o: src/core/ext/transport/chttp2/server/insecure/server_chttp2_posix.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/transport/chttp2/server/insecure
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/transport/chttp2/server/insecure/server_chttp2_posix.o src/core/ext/transport/chttp2/server/insecure/server_chttp2_posix.c

${OBJECTDIR}/src/core/ext/transport/chttp2/server/secure/server_secure_chttp2.o: src/core/ext/transport/chttp2/server/secure/server_secure_chttp2.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/transport/chttp2/server/secure
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/transport/chttp2/server/secure/server_secure_chttp2.o src/core/ext/transport/chttp2/server/secure/server_secure_chttp2.c

${OBJECTDIR}/src/core/ext/transport/chttp2/transport/bin_decoder.o: src/core/ext/transport/chttp2/transport/bin_decoder.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/transport/chttp2/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/transport/chttp2/transport/bin_decoder.o src/core/ext/transport/chttp2/transport/bin_decoder.c

${OBJECTDIR}/src/core/ext/transport/chttp2/transport/bin_encoder.o: src/core/ext/transport/chttp2/transport/bin_encoder.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/transport/chttp2/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/transport/chttp2/transport/bin_encoder.o src/core/ext/transport/chttp2/transport/bin_encoder.c

${OBJECTDIR}/src/core/ext/transport/chttp2/transport/chttp2_plugin.o: src/core/ext/transport/chttp2/transport/chttp2_plugin.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/transport/chttp2/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/transport/chttp2/transport/chttp2_plugin.o src/core/ext/transport/chttp2/transport/chttp2_plugin.c

${OBJECTDIR}/src/core/ext/transport/chttp2/transport/chttp2_transport.o: src/core/ext/transport/chttp2/transport/chttp2_transport.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/transport/chttp2/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/transport/chttp2/transport/chttp2_transport.o src/core/ext/transport/chttp2/transport/chttp2_transport.c

${OBJECTDIR}/src/core/ext/transport/chttp2/transport/frame_data.o: src/core/ext/transport/chttp2/transport/frame_data.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/transport/chttp2/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/transport/chttp2/transport/frame_data.o src/core/ext/transport/chttp2/transport/frame_data.c

${OBJECTDIR}/src/core/ext/transport/chttp2/transport/frame_goaway.o: src/core/ext/transport/chttp2/transport/frame_goaway.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/transport/chttp2/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/transport/chttp2/transport/frame_goaway.o src/core/ext/transport/chttp2/transport/frame_goaway.c

${OBJECTDIR}/src/core/ext/transport/chttp2/transport/frame_ping.o: src/core/ext/transport/chttp2/transport/frame_ping.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/transport/chttp2/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/transport/chttp2/transport/frame_ping.o src/core/ext/transport/chttp2/transport/frame_ping.c

${OBJECTDIR}/src/core/ext/transport/chttp2/transport/frame_rst_stream.o: src/core/ext/transport/chttp2/transport/frame_rst_stream.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/transport/chttp2/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/transport/chttp2/transport/frame_rst_stream.o src/core/ext/transport/chttp2/transport/frame_rst_stream.c

${OBJECTDIR}/src/core/ext/transport/chttp2/transport/frame_settings.o: src/core/ext/transport/chttp2/transport/frame_settings.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/transport/chttp2/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/transport/chttp2/transport/frame_settings.o src/core/ext/transport/chttp2/transport/frame_settings.c

${OBJECTDIR}/src/core/ext/transport/chttp2/transport/frame_window_update.o: src/core/ext/transport/chttp2/transport/frame_window_update.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/transport/chttp2/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/transport/chttp2/transport/frame_window_update.o src/core/ext/transport/chttp2/transport/frame_window_update.c

${OBJECTDIR}/src/core/ext/transport/chttp2/transport/hpack_encoder.o: src/core/ext/transport/chttp2/transport/hpack_encoder.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/transport/chttp2/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/transport/chttp2/transport/hpack_encoder.o src/core/ext/transport/chttp2/transport/hpack_encoder.c

${OBJECTDIR}/src/core/ext/transport/chttp2/transport/hpack_parser.o: src/core/ext/transport/chttp2/transport/hpack_parser.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/transport/chttp2/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/transport/chttp2/transport/hpack_parser.o src/core/ext/transport/chttp2/transport/hpack_parser.c

${OBJECTDIR}/src/core/ext/transport/chttp2/transport/hpack_table.o: src/core/ext/transport/chttp2/transport/hpack_table.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/transport/chttp2/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/transport/chttp2/transport/hpack_table.o src/core/ext/transport/chttp2/transport/hpack_table.c

${OBJECTDIR}/src/core/ext/transport/chttp2/transport/http2_settings.o: src/core/ext/transport/chttp2/transport/http2_settings.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/transport/chttp2/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/transport/chttp2/transport/http2_settings.o src/core/ext/transport/chttp2/transport/http2_settings.c

${OBJECTDIR}/src/core/ext/transport/chttp2/transport/huffsyms.o: src/core/ext/transport/chttp2/transport/huffsyms.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/transport/chttp2/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/transport/chttp2/transport/huffsyms.o src/core/ext/transport/chttp2/transport/huffsyms.c

${OBJECTDIR}/src/core/ext/transport/chttp2/transport/incoming_metadata.o: src/core/ext/transport/chttp2/transport/incoming_metadata.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/transport/chttp2/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/transport/chttp2/transport/incoming_metadata.o src/core/ext/transport/chttp2/transport/incoming_metadata.c

${OBJECTDIR}/src/core/ext/transport/chttp2/transport/parsing.o: src/core/ext/transport/chttp2/transport/parsing.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/transport/chttp2/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/transport/chttp2/transport/parsing.o src/core/ext/transport/chttp2/transport/parsing.c

${OBJECTDIR}/src/core/ext/transport/chttp2/transport/stream_lists.o: src/core/ext/transport/chttp2/transport/stream_lists.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/transport/chttp2/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/transport/chttp2/transport/stream_lists.o src/core/ext/transport/chttp2/transport/stream_lists.c

${OBJECTDIR}/src/core/ext/transport/chttp2/transport/stream_map.o: src/core/ext/transport/chttp2/transport/stream_map.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/transport/chttp2/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/transport/chttp2/transport/stream_map.o src/core/ext/transport/chttp2/transport/stream_map.c

${OBJECTDIR}/src/core/ext/transport/chttp2/transport/varint.o: src/core/ext/transport/chttp2/transport/varint.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/transport/chttp2/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/transport/chttp2/transport/varint.o src/core/ext/transport/chttp2/transport/varint.c

${OBJECTDIR}/src/core/ext/transport/chttp2/transport/writing.o: src/core/ext/transport/chttp2/transport/writing.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/transport/chttp2/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/transport/chttp2/transport/writing.o src/core/ext/transport/chttp2/transport/writing.c

${OBJECTDIR}/src/core/ext/transport/cronet/client/secure/cronet_channel_create.o: src/core/ext/transport/cronet/client/secure/cronet_channel_create.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/transport/cronet/client/secure
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/transport/cronet/client/secure/cronet_channel_create.o src/core/ext/transport/cronet/client/secure/cronet_channel_create.c

${OBJECTDIR}/src/core/ext/transport/cronet/transport/cronet_api_dummy.o: src/core/ext/transport/cronet/transport/cronet_api_dummy.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/transport/cronet/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/transport/cronet/transport/cronet_api_dummy.o src/core/ext/transport/cronet/transport/cronet_api_dummy.c

${OBJECTDIR}/src/core/ext/transport/cronet/transport/cronet_transport.o: src/core/ext/transport/cronet/transport/cronet_transport.c
	${MKDIR} -p ${OBJECTDIR}/src/core/ext/transport/cronet/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/ext/transport/cronet/transport/cronet_transport.o src/core/ext/transport/cronet/transport/cronet_transport.c

${OBJECTDIR}/src/core/lib/channel/channel_args.o: src/core/lib/channel/channel_args.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/channel
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/channel/channel_args.o src/core/lib/channel/channel_args.c

${OBJECTDIR}/src/core/lib/channel/channel_stack.o: src/core/lib/channel/channel_stack.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/channel
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/channel/channel_stack.o src/core/lib/channel/channel_stack.c

${OBJECTDIR}/src/core/lib/channel/channel_stack_builder.o: src/core/lib/channel/channel_stack_builder.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/channel
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/channel/channel_stack_builder.o src/core/lib/channel/channel_stack_builder.c

${OBJECTDIR}/src/core/lib/channel/connected_channel.o: src/core/lib/channel/connected_channel.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/channel
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/channel/connected_channel.o src/core/lib/channel/connected_channel.c

${OBJECTDIR}/src/core/lib/channel/handshaker.o: src/core/lib/channel/handshaker.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/channel
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/channel/handshaker.o src/core/lib/channel/handshaker.c

${OBJECTDIR}/src/core/lib/channel/handshaker_factory.o: src/core/lib/channel/handshaker_factory.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/channel
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/channel/handshaker_factory.o src/core/lib/channel/handshaker_factory.c

${OBJECTDIR}/src/core/lib/channel/handshaker_registry.o: src/core/lib/channel/handshaker_registry.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/channel
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/channel/handshaker_registry.o src/core/lib/channel/handshaker_registry.c

${OBJECTDIR}/src/core/lib/compression/compression.o: src/core/lib/compression/compression.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/compression
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/compression/compression.o src/core/lib/compression/compression.c

${OBJECTDIR}/src/core/lib/compression/message_compress.o: src/core/lib/compression/message_compress.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/compression
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/compression/message_compress.o src/core/lib/compression/message_compress.c

${OBJECTDIR}/src/core/lib/debug/trace.o: src/core/lib/debug/trace.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/debug
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/debug/trace.o src/core/lib/debug/trace.c

${OBJECTDIR}/src/core/lib/http/format_request.o: src/core/lib/http/format_request.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/http
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/http/format_request.o src/core/lib/http/format_request.c

${OBJECTDIR}/src/core/lib/http/httpcli.o: src/core/lib/http/httpcli.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/http
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/http/httpcli.o src/core/lib/http/httpcli.c

${OBJECTDIR}/src/core/lib/http/httpcli_security_connector.o: src/core/lib/http/httpcli_security_connector.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/http
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/http/httpcli_security_connector.o src/core/lib/http/httpcli_security_connector.c

${OBJECTDIR}/src/core/lib/http/parser.o: src/core/lib/http/parser.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/http
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/http/parser.o src/core/lib/http/parser.c

${OBJECTDIR}/src/core/lib/iomgr/closure.o: src/core/lib/iomgr/closure.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/closure.o src/core/lib/iomgr/closure.c

${OBJECTDIR}/src/core/lib/iomgr/combiner.o: src/core/lib/iomgr/combiner.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/combiner.o src/core/lib/iomgr/combiner.c

${OBJECTDIR}/src/core/lib/iomgr/endpoint.o: src/core/lib/iomgr/endpoint.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/endpoint.o src/core/lib/iomgr/endpoint.c

${OBJECTDIR}/src/core/lib/iomgr/endpoint_pair_posix.o: src/core/lib/iomgr/endpoint_pair_posix.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/endpoint_pair_posix.o src/core/lib/iomgr/endpoint_pair_posix.c

${OBJECTDIR}/src/core/lib/iomgr/endpoint_pair_uv.o: src/core/lib/iomgr/endpoint_pair_uv.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/endpoint_pair_uv.o src/core/lib/iomgr/endpoint_pair_uv.c

${OBJECTDIR}/src/core/lib/iomgr/endpoint_pair_windows.o: src/core/lib/iomgr/endpoint_pair_windows.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/endpoint_pair_windows.o src/core/lib/iomgr/endpoint_pair_windows.c

${OBJECTDIR}/src/core/lib/iomgr/error.o: src/core/lib/iomgr/error.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/error.o src/core/lib/iomgr/error.c

${OBJECTDIR}/src/core/lib/iomgr/ev_epoll1_linux.o: src/core/lib/iomgr/ev_epoll1_linux.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/ev_epoll1_linux.o src/core/lib/iomgr/ev_epoll1_linux.c

${OBJECTDIR}/src/core/lib/iomgr/ev_epoll_limited_pollers_linux.o: src/core/lib/iomgr/ev_epoll_limited_pollers_linux.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/ev_epoll_limited_pollers_linux.o src/core/lib/iomgr/ev_epoll_limited_pollers_linux.c

${OBJECTDIR}/src/core/lib/iomgr/ev_epoll_thread_pool_linux.o: src/core/lib/iomgr/ev_epoll_thread_pool_linux.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/ev_epoll_thread_pool_linux.o src/core/lib/iomgr/ev_epoll_thread_pool_linux.c

${OBJECTDIR}/src/core/lib/iomgr/ev_epollex_linux.o: src/core/lib/iomgr/ev_epollex_linux.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/ev_epollex_linux.o src/core/lib/iomgr/ev_epollex_linux.c

${OBJECTDIR}/src/core/lib/iomgr/ev_epollsig_linux.o: src/core/lib/iomgr/ev_epollsig_linux.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/ev_epollsig_linux.o src/core/lib/iomgr/ev_epollsig_linux.c

${OBJECTDIR}/src/core/lib/iomgr/ev_poll_posix.o: src/core/lib/iomgr/ev_poll_posix.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/ev_poll_posix.o src/core/lib/iomgr/ev_poll_posix.c

${OBJECTDIR}/src/core/lib/iomgr/ev_posix.o: src/core/lib/iomgr/ev_posix.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/ev_posix.o src/core/lib/iomgr/ev_posix.c

${OBJECTDIR}/src/core/lib/iomgr/ev_windows.o: src/core/lib/iomgr/ev_windows.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/ev_windows.o src/core/lib/iomgr/ev_windows.c

${OBJECTDIR}/src/core/lib/iomgr/exec_ctx.o: src/core/lib/iomgr/exec_ctx.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/exec_ctx.o src/core/lib/iomgr/exec_ctx.c

${OBJECTDIR}/src/core/lib/iomgr/executor.o: src/core/lib/iomgr/executor.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/executor.o src/core/lib/iomgr/executor.c

${OBJECTDIR}/src/core/lib/iomgr/iocp_windows.o: src/core/lib/iomgr/iocp_windows.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/iocp_windows.o src/core/lib/iomgr/iocp_windows.c

${OBJECTDIR}/src/core/lib/iomgr/iomgr.o: src/core/lib/iomgr/iomgr.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/iomgr.o src/core/lib/iomgr/iomgr.c

${OBJECTDIR}/src/core/lib/iomgr/iomgr_posix.o: src/core/lib/iomgr/iomgr_posix.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/iomgr_posix.o src/core/lib/iomgr/iomgr_posix.c

${OBJECTDIR}/src/core/lib/iomgr/iomgr_uv.o: src/core/lib/iomgr/iomgr_uv.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/iomgr_uv.o src/core/lib/iomgr/iomgr_uv.c

${OBJECTDIR}/src/core/lib/iomgr/iomgr_windows.o: src/core/lib/iomgr/iomgr_windows.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/iomgr_windows.o src/core/lib/iomgr/iomgr_windows.c

${OBJECTDIR}/src/core/lib/iomgr/is_epollexclusive_available.o: src/core/lib/iomgr/is_epollexclusive_available.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/is_epollexclusive_available.o src/core/lib/iomgr/is_epollexclusive_available.c

${OBJECTDIR}/src/core/lib/iomgr/load_file.o: src/core/lib/iomgr/load_file.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/load_file.o src/core/lib/iomgr/load_file.c

${OBJECTDIR}/src/core/lib/iomgr/lockfree_event.o: src/core/lib/iomgr/lockfree_event.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/lockfree_event.o src/core/lib/iomgr/lockfree_event.c

${OBJECTDIR}/src/core/lib/iomgr/network_status_tracker.o: src/core/lib/iomgr/network_status_tracker.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/network_status_tracker.o src/core/lib/iomgr/network_status_tracker.c

${OBJECTDIR}/src/core/lib/iomgr/polling_entity.o: src/core/lib/iomgr/polling_entity.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/polling_entity.o src/core/lib/iomgr/polling_entity.c

${OBJECTDIR}/src/core/lib/iomgr/pollset_set_uv.o: src/core/lib/iomgr/pollset_set_uv.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/pollset_set_uv.o src/core/lib/iomgr/pollset_set_uv.c

${OBJECTDIR}/src/core/lib/iomgr/pollset_set_windows.o: src/core/lib/iomgr/pollset_set_windows.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/pollset_set_windows.o src/core/lib/iomgr/pollset_set_windows.c

${OBJECTDIR}/src/core/lib/iomgr/pollset_uv.o: src/core/lib/iomgr/pollset_uv.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/pollset_uv.o src/core/lib/iomgr/pollset_uv.c

${OBJECTDIR}/src/core/lib/iomgr/pollset_windows.o: src/core/lib/iomgr/pollset_windows.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/pollset_windows.o src/core/lib/iomgr/pollset_windows.c

${OBJECTDIR}/src/core/lib/iomgr/resolve_address_posix.o: src/core/lib/iomgr/resolve_address_posix.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/resolve_address_posix.o src/core/lib/iomgr/resolve_address_posix.c

${OBJECTDIR}/src/core/lib/iomgr/resolve_address_uv.o: src/core/lib/iomgr/resolve_address_uv.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/resolve_address_uv.o src/core/lib/iomgr/resolve_address_uv.c

${OBJECTDIR}/src/core/lib/iomgr/resolve_address_windows.o: src/core/lib/iomgr/resolve_address_windows.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/resolve_address_windows.o src/core/lib/iomgr/resolve_address_windows.c

${OBJECTDIR}/src/core/lib/iomgr/resource_quota.o: src/core/lib/iomgr/resource_quota.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/resource_quota.o src/core/lib/iomgr/resource_quota.c

${OBJECTDIR}/src/core/lib/iomgr/sockaddr_utils.o: src/core/lib/iomgr/sockaddr_utils.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/sockaddr_utils.o src/core/lib/iomgr/sockaddr_utils.c

${OBJECTDIR}/src/core/lib/iomgr/socket_factory_posix.o: src/core/lib/iomgr/socket_factory_posix.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/socket_factory_posix.o src/core/lib/iomgr/socket_factory_posix.c

${OBJECTDIR}/src/core/lib/iomgr/socket_mutator.o: src/core/lib/iomgr/socket_mutator.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/socket_mutator.o src/core/lib/iomgr/socket_mutator.c

${OBJECTDIR}/src/core/lib/iomgr/socket_utils_common_posix.o: src/core/lib/iomgr/socket_utils_common_posix.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/socket_utils_common_posix.o src/core/lib/iomgr/socket_utils_common_posix.c

${OBJECTDIR}/src/core/lib/iomgr/socket_utils_linux.o: src/core/lib/iomgr/socket_utils_linux.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/socket_utils_linux.o src/core/lib/iomgr/socket_utils_linux.c

${OBJECTDIR}/src/core/lib/iomgr/socket_utils_posix.o: src/core/lib/iomgr/socket_utils_posix.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/socket_utils_posix.o src/core/lib/iomgr/socket_utils_posix.c

${OBJECTDIR}/src/core/lib/iomgr/socket_utils_uv.o: src/core/lib/iomgr/socket_utils_uv.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/socket_utils_uv.o src/core/lib/iomgr/socket_utils_uv.c

${OBJECTDIR}/src/core/lib/iomgr/socket_utils_windows.o: src/core/lib/iomgr/socket_utils_windows.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/socket_utils_windows.o src/core/lib/iomgr/socket_utils_windows.c

${OBJECTDIR}/src/core/lib/iomgr/socket_windows.o: src/core/lib/iomgr/socket_windows.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/socket_windows.o src/core/lib/iomgr/socket_windows.c

${OBJECTDIR}/src/core/lib/iomgr/tcp_client_posix.o: src/core/lib/iomgr/tcp_client_posix.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/tcp_client_posix.o src/core/lib/iomgr/tcp_client_posix.c

${OBJECTDIR}/src/core/lib/iomgr/tcp_client_uv.o: src/core/lib/iomgr/tcp_client_uv.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/tcp_client_uv.o src/core/lib/iomgr/tcp_client_uv.c

${OBJECTDIR}/src/core/lib/iomgr/tcp_client_windows.o: src/core/lib/iomgr/tcp_client_windows.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/tcp_client_windows.o src/core/lib/iomgr/tcp_client_windows.c

${OBJECTDIR}/src/core/lib/iomgr/tcp_posix.o: src/core/lib/iomgr/tcp_posix.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/tcp_posix.o src/core/lib/iomgr/tcp_posix.c

${OBJECTDIR}/src/core/lib/iomgr/tcp_server_posix.o: src/core/lib/iomgr/tcp_server_posix.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/tcp_server_posix.o src/core/lib/iomgr/tcp_server_posix.c

${OBJECTDIR}/src/core/lib/iomgr/tcp_server_utils_posix_common.o: src/core/lib/iomgr/tcp_server_utils_posix_common.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/tcp_server_utils_posix_common.o src/core/lib/iomgr/tcp_server_utils_posix_common.c

${OBJECTDIR}/src/core/lib/iomgr/tcp_server_utils_posix_ifaddrs.o: src/core/lib/iomgr/tcp_server_utils_posix_ifaddrs.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/tcp_server_utils_posix_ifaddrs.o src/core/lib/iomgr/tcp_server_utils_posix_ifaddrs.c

${OBJECTDIR}/src/core/lib/iomgr/tcp_server_utils_posix_noifaddrs.o: src/core/lib/iomgr/tcp_server_utils_posix_noifaddrs.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/tcp_server_utils_posix_noifaddrs.o src/core/lib/iomgr/tcp_server_utils_posix_noifaddrs.c

${OBJECTDIR}/src/core/lib/iomgr/tcp_server_uv.o: src/core/lib/iomgr/tcp_server_uv.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/tcp_server_uv.o src/core/lib/iomgr/tcp_server_uv.c

${OBJECTDIR}/src/core/lib/iomgr/tcp_server_windows.o: src/core/lib/iomgr/tcp_server_windows.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/tcp_server_windows.o src/core/lib/iomgr/tcp_server_windows.c

${OBJECTDIR}/src/core/lib/iomgr/tcp_uv.o: src/core/lib/iomgr/tcp_uv.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/tcp_uv.o src/core/lib/iomgr/tcp_uv.c

${OBJECTDIR}/src/core/lib/iomgr/tcp_windows.o: src/core/lib/iomgr/tcp_windows.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/tcp_windows.o src/core/lib/iomgr/tcp_windows.c

${OBJECTDIR}/src/core/lib/iomgr/time_averaged_stats.o: src/core/lib/iomgr/time_averaged_stats.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/time_averaged_stats.o src/core/lib/iomgr/time_averaged_stats.c

${OBJECTDIR}/src/core/lib/iomgr/timer_generic.o: src/core/lib/iomgr/timer_generic.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/timer_generic.o src/core/lib/iomgr/timer_generic.c

${OBJECTDIR}/src/core/lib/iomgr/timer_heap.o: src/core/lib/iomgr/timer_heap.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/timer_heap.o src/core/lib/iomgr/timer_heap.c

${OBJECTDIR}/src/core/lib/iomgr/timer_manager.o: src/core/lib/iomgr/timer_manager.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/timer_manager.o src/core/lib/iomgr/timer_manager.c

${OBJECTDIR}/src/core/lib/iomgr/timer_uv.o: src/core/lib/iomgr/timer_uv.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/timer_uv.o src/core/lib/iomgr/timer_uv.c

${OBJECTDIR}/src/core/lib/iomgr/udp_server.o: src/core/lib/iomgr/udp_server.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/udp_server.o src/core/lib/iomgr/udp_server.c

${OBJECTDIR}/src/core/lib/iomgr/unix_sockets_posix.o: src/core/lib/iomgr/unix_sockets_posix.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/unix_sockets_posix.o src/core/lib/iomgr/unix_sockets_posix.c

${OBJECTDIR}/src/core/lib/iomgr/unix_sockets_posix_noop.o: src/core/lib/iomgr/unix_sockets_posix_noop.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/unix_sockets_posix_noop.o src/core/lib/iomgr/unix_sockets_posix_noop.c

${OBJECTDIR}/src/core/lib/iomgr/wakeup_fd_cv.o: src/core/lib/iomgr/wakeup_fd_cv.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/wakeup_fd_cv.o src/core/lib/iomgr/wakeup_fd_cv.c

${OBJECTDIR}/src/core/lib/iomgr/wakeup_fd_eventfd.o: src/core/lib/iomgr/wakeup_fd_eventfd.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/wakeup_fd_eventfd.o src/core/lib/iomgr/wakeup_fd_eventfd.c

${OBJECTDIR}/src/core/lib/iomgr/wakeup_fd_nospecial.o: src/core/lib/iomgr/wakeup_fd_nospecial.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/wakeup_fd_nospecial.o src/core/lib/iomgr/wakeup_fd_nospecial.c

${OBJECTDIR}/src/core/lib/iomgr/wakeup_fd_pipe.o: src/core/lib/iomgr/wakeup_fd_pipe.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/wakeup_fd_pipe.o src/core/lib/iomgr/wakeup_fd_pipe.c

${OBJECTDIR}/src/core/lib/iomgr/wakeup_fd_posix.o: src/core/lib/iomgr/wakeup_fd_posix.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/wakeup_fd_posix.o src/core/lib/iomgr/wakeup_fd_posix.c

${OBJECTDIR}/src/core/lib/iomgr/workqueue_uv.o: src/core/lib/iomgr/workqueue_uv.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/workqueue_uv.o src/core/lib/iomgr/workqueue_uv.c

${OBJECTDIR}/src/core/lib/iomgr/workqueue_windows.o: src/core/lib/iomgr/workqueue_windows.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/iomgr
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/iomgr/workqueue_windows.o src/core/lib/iomgr/workqueue_windows.c

${OBJECTDIR}/src/core/lib/json/json.o: src/core/lib/json/json.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/json
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/json/json.o src/core/lib/json/json.c

${OBJECTDIR}/src/core/lib/json/json_reader.o: src/core/lib/json/json_reader.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/json
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/json/json_reader.o src/core/lib/json/json_reader.c

${OBJECTDIR}/src/core/lib/json/json_string.o: src/core/lib/json/json_string.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/json
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/json/json_string.o src/core/lib/json/json_string.c

${OBJECTDIR}/src/core/lib/json/json_writer.o: src/core/lib/json/json_writer.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/json
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/json/json_writer.o src/core/lib/json/json_writer.c

${OBJECTDIR}/src/core/lib/profiling/basic_timers.o: src/core/lib/profiling/basic_timers.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/profiling
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/profiling/basic_timers.o src/core/lib/profiling/basic_timers.c

${OBJECTDIR}/src/core/lib/profiling/stap_timers.o: src/core/lib/profiling/stap_timers.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/profiling
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/profiling/stap_timers.o src/core/lib/profiling/stap_timers.c

${OBJECTDIR}/src/core/lib/security/context/security_context.o: src/core/lib/security/context/security_context.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/security/context
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/security/context/security_context.o src/core/lib/security/context/security_context.c

${OBJECTDIR}/src/core/lib/security/credentials/composite/composite_credentials.o: src/core/lib/security/credentials/composite/composite_credentials.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/security/credentials/composite
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/security/credentials/composite/composite_credentials.o src/core/lib/security/credentials/composite/composite_credentials.c

${OBJECTDIR}/src/core/lib/security/credentials/credentials.o: src/core/lib/security/credentials/credentials.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/security/credentials
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/security/credentials/credentials.o src/core/lib/security/credentials/credentials.c

${OBJECTDIR}/src/core/lib/security/credentials/credentials_metadata.o: src/core/lib/security/credentials/credentials_metadata.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/security/credentials
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/security/credentials/credentials_metadata.o src/core/lib/security/credentials/credentials_metadata.c

${OBJECTDIR}/src/core/lib/security/credentials/fake/fake_credentials.o: src/core/lib/security/credentials/fake/fake_credentials.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/security/credentials/fake
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/security/credentials/fake/fake_credentials.o src/core/lib/security/credentials/fake/fake_credentials.c

${OBJECTDIR}/src/core/lib/security/credentials/google_default/credentials_generic.o: src/core/lib/security/credentials/google_default/credentials_generic.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/security/credentials/google_default
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/security/credentials/google_default/credentials_generic.o src/core/lib/security/credentials/google_default/credentials_generic.c

${OBJECTDIR}/src/core/lib/security/credentials/google_default/google_default_credentials.o: src/core/lib/security/credentials/google_default/google_default_credentials.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/security/credentials/google_default
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/security/credentials/google_default/google_default_credentials.o src/core/lib/security/credentials/google_default/google_default_credentials.c

${OBJECTDIR}/src/core/lib/security/credentials/iam/iam_credentials.o: src/core/lib/security/credentials/iam/iam_credentials.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/security/credentials/iam
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/security/credentials/iam/iam_credentials.o src/core/lib/security/credentials/iam/iam_credentials.c

${OBJECTDIR}/src/core/lib/security/credentials/jwt/json_token.o: src/core/lib/security/credentials/jwt/json_token.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/security/credentials/jwt
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/security/credentials/jwt/json_token.o src/core/lib/security/credentials/jwt/json_token.c

${OBJECTDIR}/src/core/lib/security/credentials/jwt/jwt_credentials.o: src/core/lib/security/credentials/jwt/jwt_credentials.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/security/credentials/jwt
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/security/credentials/jwt/jwt_credentials.o src/core/lib/security/credentials/jwt/jwt_credentials.c

${OBJECTDIR}/src/core/lib/security/credentials/jwt/jwt_verifier.o: src/core/lib/security/credentials/jwt/jwt_verifier.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/security/credentials/jwt
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/security/credentials/jwt/jwt_verifier.o src/core/lib/security/credentials/jwt/jwt_verifier.c

${OBJECTDIR}/src/core/lib/security/credentials/oauth2/oauth2_credentials.o: src/core/lib/security/credentials/oauth2/oauth2_credentials.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/security/credentials/oauth2
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/security/credentials/oauth2/oauth2_credentials.o src/core/lib/security/credentials/oauth2/oauth2_credentials.c

${OBJECTDIR}/src/core/lib/security/credentials/plugin/plugin_credentials.o: src/core/lib/security/credentials/plugin/plugin_credentials.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/security/credentials/plugin
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/security/credentials/plugin/plugin_credentials.o src/core/lib/security/credentials/plugin/plugin_credentials.c

${OBJECTDIR}/src/core/lib/security/credentials/ssl/ssl_credentials.o: src/core/lib/security/credentials/ssl/ssl_credentials.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/security/credentials/ssl
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/security/credentials/ssl/ssl_credentials.o src/core/lib/security/credentials/ssl/ssl_credentials.c

${OBJECTDIR}/src/core/lib/security/transport/client_auth_filter.o: src/core/lib/security/transport/client_auth_filter.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/security/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/security/transport/client_auth_filter.o src/core/lib/security/transport/client_auth_filter.c

${OBJECTDIR}/src/core/lib/security/transport/lb_targets_info.o: src/core/lib/security/transport/lb_targets_info.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/security/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/security/transport/lb_targets_info.o src/core/lib/security/transport/lb_targets_info.c

${OBJECTDIR}/src/core/lib/security/transport/secure_endpoint.o: src/core/lib/security/transport/secure_endpoint.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/security/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/security/transport/secure_endpoint.o src/core/lib/security/transport/secure_endpoint.c

${OBJECTDIR}/src/core/lib/security/transport/security_connector.o: src/core/lib/security/transport/security_connector.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/security/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/security/transport/security_connector.o src/core/lib/security/transport/security_connector.c

${OBJECTDIR}/src/core/lib/security/transport/security_handshaker.o: src/core/lib/security/transport/security_handshaker.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/security/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/security/transport/security_handshaker.o src/core/lib/security/transport/security_handshaker.c

${OBJECTDIR}/src/core/lib/security/transport/server_auth_filter.o: src/core/lib/security/transport/server_auth_filter.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/security/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/security/transport/server_auth_filter.o src/core/lib/security/transport/server_auth_filter.c

${OBJECTDIR}/src/core/lib/security/transport/tsi_error.o: src/core/lib/security/transport/tsi_error.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/security/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/security/transport/tsi_error.o src/core/lib/security/transport/tsi_error.c

${OBJECTDIR}/src/core/lib/security/util/json_util.o: src/core/lib/security/util/json_util.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/security/util
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/security/util/json_util.o src/core/lib/security/util/json_util.c

${OBJECTDIR}/src/core/lib/slice/b64.o: src/core/lib/slice/b64.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/slice
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/slice/b64.o src/core/lib/slice/b64.c

${OBJECTDIR}/src/core/lib/slice/percent_encoding.o: src/core/lib/slice/percent_encoding.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/slice
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/slice/percent_encoding.o src/core/lib/slice/percent_encoding.c

${OBJECTDIR}/src/core/lib/slice/slice.o: src/core/lib/slice/slice.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/slice
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/slice/slice.o src/core/lib/slice/slice.c

${OBJECTDIR}/src/core/lib/slice/slice_buffer.o: src/core/lib/slice/slice_buffer.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/slice
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/slice/slice_buffer.o src/core/lib/slice/slice_buffer.c

${OBJECTDIR}/src/core/lib/slice/slice_hash_table.o: src/core/lib/slice/slice_hash_table.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/slice
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/slice/slice_hash_table.o src/core/lib/slice/slice_hash_table.c

${OBJECTDIR}/src/core/lib/slice/slice_intern.o: src/core/lib/slice/slice_intern.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/slice
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/slice/slice_intern.o src/core/lib/slice/slice_intern.c

${OBJECTDIR}/src/core/lib/slice/slice_string_helpers.o: src/core/lib/slice/slice_string_helpers.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/slice
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/slice/slice_string_helpers.o src/core/lib/slice/slice_string_helpers.c

${OBJECTDIR}/src/core/lib/support/alloc.o: src/core/lib/support/alloc.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/alloc.o src/core/lib/support/alloc.c

${OBJECTDIR}/src/core/lib/support/arena.o: src/core/lib/support/arena.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/arena.o src/core/lib/support/arena.c

${OBJECTDIR}/src/core/lib/support/atm.o: src/core/lib/support/atm.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/atm.o src/core/lib/support/atm.c

${OBJECTDIR}/src/core/lib/support/avl.o: src/core/lib/support/avl.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/avl.o src/core/lib/support/avl.c

${OBJECTDIR}/src/core/lib/support/backoff.o: src/core/lib/support/backoff.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/backoff.o src/core/lib/support/backoff.c

${OBJECTDIR}/src/core/lib/support/cmdline.o: src/core/lib/support/cmdline.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/cmdline.o src/core/lib/support/cmdline.c

${OBJECTDIR}/src/core/lib/support/cpu_iphone.o: src/core/lib/support/cpu_iphone.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/cpu_iphone.o src/core/lib/support/cpu_iphone.c

${OBJECTDIR}/src/core/lib/support/cpu_linux.o: src/core/lib/support/cpu_linux.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/cpu_linux.o src/core/lib/support/cpu_linux.c

${OBJECTDIR}/src/core/lib/support/cpu_posix.o: src/core/lib/support/cpu_posix.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/cpu_posix.o src/core/lib/support/cpu_posix.c

${OBJECTDIR}/src/core/lib/support/cpu_windows.o: src/core/lib/support/cpu_windows.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/cpu_windows.o src/core/lib/support/cpu_windows.c

${OBJECTDIR}/src/core/lib/support/env_linux.o: src/core/lib/support/env_linux.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/env_linux.o src/core/lib/support/env_linux.c

${OBJECTDIR}/src/core/lib/support/env_posix.o: src/core/lib/support/env_posix.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/env_posix.o src/core/lib/support/env_posix.c

${OBJECTDIR}/src/core/lib/support/env_windows.o: src/core/lib/support/env_windows.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/env_windows.o src/core/lib/support/env_windows.c

${OBJECTDIR}/src/core/lib/support/histogram.o: src/core/lib/support/histogram.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/histogram.o src/core/lib/support/histogram.c

${OBJECTDIR}/src/core/lib/support/host_port.o: src/core/lib/support/host_port.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/host_port.o src/core/lib/support/host_port.c

${OBJECTDIR}/src/core/lib/support/log.o: src/core/lib/support/log.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/log.o src/core/lib/support/log.c

${OBJECTDIR}/src/core/lib/support/log_android.o: src/core/lib/support/log_android.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/log_android.o src/core/lib/support/log_android.c

${OBJECTDIR}/src/core/lib/support/log_linux.o: src/core/lib/support/log_linux.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/log_linux.o src/core/lib/support/log_linux.c

${OBJECTDIR}/src/core/lib/support/log_posix.o: src/core/lib/support/log_posix.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/log_posix.o src/core/lib/support/log_posix.c

${OBJECTDIR}/src/core/lib/support/log_windows.o: src/core/lib/support/log_windows.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/log_windows.o src/core/lib/support/log_windows.c

${OBJECTDIR}/src/core/lib/support/mpscq.o: src/core/lib/support/mpscq.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/mpscq.o src/core/lib/support/mpscq.c

${OBJECTDIR}/src/core/lib/support/murmur_hash.o: src/core/lib/support/murmur_hash.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/murmur_hash.o src/core/lib/support/murmur_hash.c

${OBJECTDIR}/src/core/lib/support/stack_lockfree.o: src/core/lib/support/stack_lockfree.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/stack_lockfree.o src/core/lib/support/stack_lockfree.c

${OBJECTDIR}/src/core/lib/support/string.o: src/core/lib/support/string.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/string.o src/core/lib/support/string.c

${OBJECTDIR}/src/core/lib/support/string_posix.o: src/core/lib/support/string_posix.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/string_posix.o src/core/lib/support/string_posix.c

${OBJECTDIR}/src/core/lib/support/string_util_windows.o: src/core/lib/support/string_util_windows.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/string_util_windows.o src/core/lib/support/string_util_windows.c

${OBJECTDIR}/src/core/lib/support/string_windows.o: src/core/lib/support/string_windows.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/string_windows.o src/core/lib/support/string_windows.c

${OBJECTDIR}/src/core/lib/support/subprocess_posix.o: src/core/lib/support/subprocess_posix.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/subprocess_posix.o src/core/lib/support/subprocess_posix.c

${OBJECTDIR}/src/core/lib/support/subprocess_windows.o: src/core/lib/support/subprocess_windows.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/subprocess_windows.o src/core/lib/support/subprocess_windows.c

${OBJECTDIR}/src/core/lib/support/sync.o: src/core/lib/support/sync.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/sync.o src/core/lib/support/sync.c

${OBJECTDIR}/src/core/lib/support/sync_posix.o: src/core/lib/support/sync_posix.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/sync_posix.o src/core/lib/support/sync_posix.c

${OBJECTDIR}/src/core/lib/support/sync_windows.o: src/core/lib/support/sync_windows.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/sync_windows.o src/core/lib/support/sync_windows.c

${OBJECTDIR}/src/core/lib/support/thd.o: src/core/lib/support/thd.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/thd.o src/core/lib/support/thd.c

${OBJECTDIR}/src/core/lib/support/thd_posix.o: src/core/lib/support/thd_posix.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/thd_posix.o src/core/lib/support/thd_posix.c

${OBJECTDIR}/src/core/lib/support/thd_windows.o: src/core/lib/support/thd_windows.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/thd_windows.o src/core/lib/support/thd_windows.c

${OBJECTDIR}/src/core/lib/support/time.o: src/core/lib/support/time.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/time.o src/core/lib/support/time.c

${OBJECTDIR}/src/core/lib/support/time_posix.o: src/core/lib/support/time_posix.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/time_posix.o src/core/lib/support/time_posix.c

${OBJECTDIR}/src/core/lib/support/time_precise.o: src/core/lib/support/time_precise.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/time_precise.o src/core/lib/support/time_precise.c

${OBJECTDIR}/src/core/lib/support/time_windows.o: src/core/lib/support/time_windows.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/time_windows.o src/core/lib/support/time_windows.c

${OBJECTDIR}/src/core/lib/support/tls_pthread.o: src/core/lib/support/tls_pthread.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/tls_pthread.o src/core/lib/support/tls_pthread.c

${OBJECTDIR}/src/core/lib/support/tmpfile_msys.o: src/core/lib/support/tmpfile_msys.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/tmpfile_msys.o src/core/lib/support/tmpfile_msys.c

${OBJECTDIR}/src/core/lib/support/tmpfile_posix.o: src/core/lib/support/tmpfile_posix.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/tmpfile_posix.o src/core/lib/support/tmpfile_posix.c

${OBJECTDIR}/src/core/lib/support/tmpfile_windows.o: src/core/lib/support/tmpfile_windows.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/tmpfile_windows.o src/core/lib/support/tmpfile_windows.c

${OBJECTDIR}/src/core/lib/support/wrap_memcpy.o: src/core/lib/support/wrap_memcpy.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/support
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/support/wrap_memcpy.o src/core/lib/support/wrap_memcpy.c

${OBJECTDIR}/src/core/lib/surface/alarm.o: src/core/lib/surface/alarm.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/surface
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/surface/alarm.o src/core/lib/surface/alarm.c

${OBJECTDIR}/src/core/lib/surface/api_trace.o: src/core/lib/surface/api_trace.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/surface
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/surface/api_trace.o src/core/lib/surface/api_trace.c

${OBJECTDIR}/src/core/lib/surface/byte_buffer.o: src/core/lib/surface/byte_buffer.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/surface
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/surface/byte_buffer.o src/core/lib/surface/byte_buffer.c

${OBJECTDIR}/src/core/lib/surface/byte_buffer_reader.o: src/core/lib/surface/byte_buffer_reader.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/surface
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/surface/byte_buffer_reader.o src/core/lib/surface/byte_buffer_reader.c

${OBJECTDIR}/src/core/lib/surface/call.o: src/core/lib/surface/call.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/surface
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/surface/call.o src/core/lib/surface/call.c

${OBJECTDIR}/src/core/lib/surface/call_details.o: src/core/lib/surface/call_details.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/surface
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/surface/call_details.o src/core/lib/surface/call_details.c

${OBJECTDIR}/src/core/lib/surface/call_log_batch.o: src/core/lib/surface/call_log_batch.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/surface
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/surface/call_log_batch.o src/core/lib/surface/call_log_batch.c

${OBJECTDIR}/src/core/lib/surface/channel.o: src/core/lib/surface/channel.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/surface
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/surface/channel.o src/core/lib/surface/channel.c

${OBJECTDIR}/src/core/lib/surface/channel_init.o: src/core/lib/surface/channel_init.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/surface
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/surface/channel_init.o src/core/lib/surface/channel_init.c

${OBJECTDIR}/src/core/lib/surface/channel_ping.o: src/core/lib/surface/channel_ping.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/surface
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/surface/channel_ping.o src/core/lib/surface/channel_ping.c

${OBJECTDIR}/src/core/lib/surface/channel_stack_type.o: src/core/lib/surface/channel_stack_type.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/surface
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/surface/channel_stack_type.o src/core/lib/surface/channel_stack_type.c

${OBJECTDIR}/src/core/lib/surface/completion_queue.o: src/core/lib/surface/completion_queue.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/surface
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/surface/completion_queue.o src/core/lib/surface/completion_queue.c

${OBJECTDIR}/src/core/lib/surface/completion_queue_factory.o: src/core/lib/surface/completion_queue_factory.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/surface
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/surface/completion_queue_factory.o src/core/lib/surface/completion_queue_factory.c

${OBJECTDIR}/src/core/lib/surface/event_string.o: src/core/lib/surface/event_string.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/surface
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/surface/event_string.o src/core/lib/surface/event_string.c

${OBJECTDIR}/src/core/lib/surface/init.o: src/core/lib/surface/init.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/surface
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/surface/init.o src/core/lib/surface/init.c

${OBJECTDIR}/src/core/lib/surface/init_secure.o: src/core/lib/surface/init_secure.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/surface
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/surface/init_secure.o src/core/lib/surface/init_secure.c

${OBJECTDIR}/src/core/lib/surface/init_unsecure.o: src/core/lib/surface/init_unsecure.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/surface
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/surface/init_unsecure.o src/core/lib/surface/init_unsecure.c

${OBJECTDIR}/src/core/lib/surface/lame_client.o: src/core/lib/surface/lame_client.cc
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/surface
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/surface/lame_client.o src/core/lib/surface/lame_client.cc

${OBJECTDIR}/src/core/lib/surface/metadata_array.o: src/core/lib/surface/metadata_array.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/surface
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/surface/metadata_array.o src/core/lib/surface/metadata_array.c

${OBJECTDIR}/src/core/lib/surface/server.o: src/core/lib/surface/server.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/surface
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/surface/server.o src/core/lib/surface/server.c

${OBJECTDIR}/src/core/lib/surface/validate_metadata.o: src/core/lib/surface/validate_metadata.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/surface
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/surface/validate_metadata.o src/core/lib/surface/validate_metadata.c

${OBJECTDIR}/src/core/lib/surface/version.o: src/core/lib/surface/version.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/surface
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/surface/version.o src/core/lib/surface/version.c

${OBJECTDIR}/src/core/lib/transport/bdp_estimator.o: src/core/lib/transport/bdp_estimator.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/transport/bdp_estimator.o src/core/lib/transport/bdp_estimator.c

${OBJECTDIR}/src/core/lib/transport/byte_stream.o: src/core/lib/transport/byte_stream.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/transport/byte_stream.o src/core/lib/transport/byte_stream.c

${OBJECTDIR}/src/core/lib/transport/connectivity_state.o: src/core/lib/transport/connectivity_state.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/transport/connectivity_state.o src/core/lib/transport/connectivity_state.c

${OBJECTDIR}/src/core/lib/transport/error_utils.o: src/core/lib/transport/error_utils.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/transport/error_utils.o src/core/lib/transport/error_utils.c

${OBJECTDIR}/src/core/lib/transport/metadata.o: src/core/lib/transport/metadata.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/transport/metadata.o src/core/lib/transport/metadata.c

${OBJECTDIR}/src/core/lib/transport/metadata_batch.o: src/core/lib/transport/metadata_batch.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/transport/metadata_batch.o src/core/lib/transport/metadata_batch.c

${OBJECTDIR}/src/core/lib/transport/pid_controller.o: src/core/lib/transport/pid_controller.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/transport/pid_controller.o src/core/lib/transport/pid_controller.c

${OBJECTDIR}/src/core/lib/transport/service_config.o: src/core/lib/transport/service_config.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/transport/service_config.o src/core/lib/transport/service_config.c

${OBJECTDIR}/src/core/lib/transport/static_metadata.o: src/core/lib/transport/static_metadata.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/transport/static_metadata.o src/core/lib/transport/static_metadata.c

${OBJECTDIR}/src/core/lib/transport/status_conversion.o: src/core/lib/transport/status_conversion.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/transport/status_conversion.o src/core/lib/transport/status_conversion.c

${OBJECTDIR}/src/core/lib/transport/timeout_encoding.o: src/core/lib/transport/timeout_encoding.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/transport/timeout_encoding.o src/core/lib/transport/timeout_encoding.c

${OBJECTDIR}/src/core/lib/transport/transport.o: src/core/lib/transport/transport.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/transport/transport.o src/core/lib/transport/transport.c

${OBJECTDIR}/src/core/lib/transport/transport_op_string.o: src/core/lib/transport/transport_op_string.c
	${MKDIR} -p ${OBJECTDIR}/src/core/lib/transport
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/lib/transport/transport_op_string.o src/core/lib/transport/transport_op_string.c

${OBJECTDIR}/src/core/plugin_registry/grpc_plugin_registry.o: src/core/plugin_registry/grpc_plugin_registry.c
	${MKDIR} -p ${OBJECTDIR}/src/core/plugin_registry
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/plugin_registry/grpc_plugin_registry.o src/core/plugin_registry/grpc_plugin_registry.c

${OBJECTDIR}/src/core/tsi/fake_transport_security.o: src/core/tsi/fake_transport_security.c
	${MKDIR} -p ${OBJECTDIR}/src/core/tsi
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/tsi/fake_transport_security.o src/core/tsi/fake_transport_security.c

${OBJECTDIR}/src/core/tsi/ssl_transport_security.o: src/core/tsi/ssl_transport_security.c
	${MKDIR} -p ${OBJECTDIR}/src/core/tsi
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/tsi/ssl_transport_security.o src/core/tsi/ssl_transport_security.c

${OBJECTDIR}/src/core/tsi/transport_security.o: src/core/tsi/transport_security.c
	${MKDIR} -p ${OBJECTDIR}/src/core/tsi
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/tsi/transport_security.o src/core/tsi/transport_security.c

${OBJECTDIR}/src/core/tsi/transport_security_adapter.o: src/core/tsi/transport_security_adapter.c
	${MKDIR} -p ${OBJECTDIR}/src/core/tsi
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/core/tsi/transport_security_adapter.o src/core/tsi/transport_security_adapter.c

${OBJECTDIR}/src/cpp/client/channel_cc.o: src/cpp/client/channel_cc.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/client
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/client/channel_cc.o src/cpp/client/channel_cc.cc

${OBJECTDIR}/src/cpp/client/client_context.o: src/cpp/client/client_context.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/client
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/client/client_context.o src/cpp/client/client_context.cc

${OBJECTDIR}/src/cpp/client/create_channel.o: src/cpp/client/create_channel.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/client
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/client/create_channel.o src/cpp/client/create_channel.cc

${OBJECTDIR}/src/cpp/client/create_channel_internal.o: src/cpp/client/create_channel_internal.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/client
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/client/create_channel_internal.o src/cpp/client/create_channel_internal.cc

${OBJECTDIR}/src/cpp/client/create_channel_posix.o: src/cpp/client/create_channel_posix.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/client
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/client/create_channel_posix.o src/cpp/client/create_channel_posix.cc

${OBJECTDIR}/src/cpp/client/credentials_cc.o: src/cpp/client/credentials_cc.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/client
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/client/credentials_cc.o src/cpp/client/credentials_cc.cc

${OBJECTDIR}/src/cpp/client/cronet_credentials.o: src/cpp/client/cronet_credentials.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/client
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/client/cronet_credentials.o src/cpp/client/cronet_credentials.cc

${OBJECTDIR}/src/cpp/client/generic_stub.o: src/cpp/client/generic_stub.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/client
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/client/generic_stub.o src/cpp/client/generic_stub.cc

${OBJECTDIR}/src/cpp/client/insecure_credentials.o: src/cpp/client/insecure_credentials.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/client
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/client/insecure_credentials.o src/cpp/client/insecure_credentials.cc

${OBJECTDIR}/src/cpp/client/secure_credentials.o: src/cpp/client/secure_credentials.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/client
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/client/secure_credentials.o src/cpp/client/secure_credentials.cc

${OBJECTDIR}/src/cpp/codegen/codegen_init.o: src/cpp/codegen/codegen_init.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/codegen
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/codegen/codegen_init.o src/cpp/codegen/codegen_init.cc

${OBJECTDIR}/src/cpp/common/auth_property_iterator.o: src/cpp/common/auth_property_iterator.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/common
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/common/auth_property_iterator.o src/cpp/common/auth_property_iterator.cc

${OBJECTDIR}/src/cpp/common/channel_arguments.o: src/cpp/common/channel_arguments.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/common
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/common/channel_arguments.o src/cpp/common/channel_arguments.cc

${OBJECTDIR}/src/cpp/common/channel_filter.o: src/cpp/common/channel_filter.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/common
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/common/channel_filter.o src/cpp/common/channel_filter.cc

${OBJECTDIR}/src/cpp/common/completion_queue_cc.o: src/cpp/common/completion_queue_cc.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/common
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/common/completion_queue_cc.o src/cpp/common/completion_queue_cc.cc

${OBJECTDIR}/src/cpp/common/core_codegen.o: src/cpp/common/core_codegen.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/common
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/common/core_codegen.o src/cpp/common/core_codegen.cc

${OBJECTDIR}/src/cpp/common/insecure_create_auth_context.o: src/cpp/common/insecure_create_auth_context.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/common
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/common/insecure_create_auth_context.o src/cpp/common/insecure_create_auth_context.cc

${OBJECTDIR}/src/cpp/common/resource_quota_cc.o: src/cpp/common/resource_quota_cc.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/common
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/common/resource_quota_cc.o src/cpp/common/resource_quota_cc.cc

${OBJECTDIR}/src/cpp/common/rpc_method.o: src/cpp/common/rpc_method.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/common
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/common/rpc_method.o src/cpp/common/rpc_method.cc

${OBJECTDIR}/src/cpp/common/secure_auth_context.o: src/cpp/common/secure_auth_context.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/common
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/common/secure_auth_context.o src/cpp/common/secure_auth_context.cc

${OBJECTDIR}/src/cpp/common/secure_channel_arguments.o: src/cpp/common/secure_channel_arguments.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/common
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/common/secure_channel_arguments.o src/cpp/common/secure_channel_arguments.cc

${OBJECTDIR}/src/cpp/common/secure_create_auth_context.o: src/cpp/common/secure_create_auth_context.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/common
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/common/secure_create_auth_context.o src/cpp/common/secure_create_auth_context.cc

${OBJECTDIR}/src/cpp/common/version_cc.o: src/cpp/common/version_cc.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/common
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/common/version_cc.o src/cpp/common/version_cc.cc

${OBJECTDIR}/src/cpp/ext/proto_server_reflection.o: src/cpp/ext/proto_server_reflection.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/ext
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/ext/proto_server_reflection.o src/cpp/ext/proto_server_reflection.cc

${OBJECTDIR}/src/cpp/ext/proto_server_reflection_plugin.o: src/cpp/ext/proto_server_reflection_plugin.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/ext
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/ext/proto_server_reflection_plugin.o src/cpp/ext/proto_server_reflection_plugin.cc

${OBJECTDIR}/src/cpp/server/async_generic_service.o: src/cpp/server/async_generic_service.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/server
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/server/async_generic_service.o src/cpp/server/async_generic_service.cc

${OBJECTDIR}/src/cpp/server/channel_argument_option.o: src/cpp/server/channel_argument_option.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/server
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/server/channel_argument_option.o src/cpp/server/channel_argument_option.cc

${OBJECTDIR}/src/cpp/server/create_default_thread_pool.o: src/cpp/server/create_default_thread_pool.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/server
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/server/create_default_thread_pool.o src/cpp/server/create_default_thread_pool.cc

${OBJECTDIR}/src/cpp/server/dynamic_thread_pool.o: src/cpp/server/dynamic_thread_pool.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/server
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/server/dynamic_thread_pool.o src/cpp/server/dynamic_thread_pool.cc

${OBJECTDIR}/src/cpp/server/health/default_health_check_service.o: src/cpp/server/health/default_health_check_service.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/server/health
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/server/health/default_health_check_service.o src/cpp/server/health/default_health_check_service.cc

${OBJECTDIR}/src/cpp/server/health/health.pb.o: src/cpp/server/health/health.pb.c
	${MKDIR} -p ${OBJECTDIR}/src/cpp/server/health
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/server/health/health.pb.o src/cpp/server/health/health.pb.c

${OBJECTDIR}/src/cpp/server/health/health_check_service.o: src/cpp/server/health/health_check_service.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/server/health
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/server/health/health_check_service.o src/cpp/server/health/health_check_service.cc

${OBJECTDIR}/src/cpp/server/health/health_check_service_server_builder_option.o: src/cpp/server/health/health_check_service_server_builder_option.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/server/health
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/server/health/health_check_service_server_builder_option.o src/cpp/server/health/health_check_service_server_builder_option.cc

${OBJECTDIR}/src/cpp/server/insecure_server_credentials.o: src/cpp/server/insecure_server_credentials.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/server
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/server/insecure_server_credentials.o src/cpp/server/insecure_server_credentials.cc

${OBJECTDIR}/src/cpp/server/secure_server_credentials.o: src/cpp/server/secure_server_credentials.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/server
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/server/secure_server_credentials.o src/cpp/server/secure_server_credentials.cc

${OBJECTDIR}/src/cpp/server/server_builder.o: src/cpp/server/server_builder.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/server
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/server/server_builder.o src/cpp/server/server_builder.cc

${OBJECTDIR}/src/cpp/server/server_cc.o: src/cpp/server/server_cc.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/server
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/server/server_cc.o src/cpp/server/server_cc.cc

${OBJECTDIR}/src/cpp/server/server_context.o: src/cpp/server/server_context.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/server
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/server/server_context.o src/cpp/server/server_context.cc

${OBJECTDIR}/src/cpp/server/server_credentials.o: src/cpp/server/server_credentials.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/server
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/server/server_credentials.o src/cpp/server/server_credentials.cc

${OBJECTDIR}/src/cpp/server/server_posix.o: src/cpp/server/server_posix.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/server
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/server/server_posix.o src/cpp/server/server_posix.cc

${OBJECTDIR}/src/cpp/thread_manager/thread_manager.o: src/cpp/thread_manager/thread_manager.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/thread_manager
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/thread_manager/thread_manager.o src/cpp/thread_manager/thread_manager.cc

${OBJECTDIR}/src/cpp/util/byte_buffer_cc.o: src/cpp/util/byte_buffer_cc.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/util
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/util/byte_buffer_cc.o src/cpp/util/byte_buffer_cc.cc

${OBJECTDIR}/src/cpp/util/error_details.o: src/cpp/util/error_details.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/util
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/util/error_details.o src/cpp/util/error_details.cc

${OBJECTDIR}/src/cpp/util/slice_cc.o: src/cpp/util/slice_cc.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/util
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/util/slice_cc.o src/cpp/util/slice_cc.cc

${OBJECTDIR}/src/cpp/util/status.o: src/cpp/util/status.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/util
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/util/status.o src/cpp/util/status.cc

${OBJECTDIR}/src/cpp/util/string_ref.o: src/cpp/util/string_ref.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/util
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/util/string_ref.o src/cpp/util/string_ref.cc

${OBJECTDIR}/src/cpp/util/time_cc.o: src/cpp/util/time_cc.cc
	${MKDIR} -p ${OBJECTDIR}/src/cpp/util
	${RM} "$@.d"
	$(COMPILE.cc) -g -Igens -I. -Iinclude -Ithird_party/cares/cares -I../LibProtobuf/include -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/src/cpp/util/time_cc.o src/cpp/util/time_cc.cc

${OBJECTDIR}/third_party/cares/cares/ares__close_sockets.o: third_party/cares/cares/ares__close_sockets.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares__close_sockets.o third_party/cares/cares/ares__close_sockets.c

${OBJECTDIR}/third_party/cares/cares/ares__get_hostent.o: third_party/cares/cares/ares__get_hostent.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares__get_hostent.o third_party/cares/cares/ares__get_hostent.c

${OBJECTDIR}/third_party/cares/cares/ares__read_line.o: third_party/cares/cares/ares__read_line.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares__read_line.o third_party/cares/cares/ares__read_line.c

${OBJECTDIR}/third_party/cares/cares/ares__timeval.o: third_party/cares/cares/ares__timeval.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares__timeval.o third_party/cares/cares/ares__timeval.c

${OBJECTDIR}/third_party/cares/cares/ares_cancel.o: third_party/cares/cares/ares_cancel.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_cancel.o third_party/cares/cares/ares_cancel.c

${OBJECTDIR}/third_party/cares/cares/ares_create_query.o: third_party/cares/cares/ares_create_query.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_create_query.o third_party/cares/cares/ares_create_query.c

${OBJECTDIR}/third_party/cares/cares/ares_data.o: third_party/cares/cares/ares_data.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_data.o third_party/cares/cares/ares_data.c

${OBJECTDIR}/third_party/cares/cares/ares_destroy.o: third_party/cares/cares/ares_destroy.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_destroy.o third_party/cares/cares/ares_destroy.c

${OBJECTDIR}/third_party/cares/cares/ares_expand_name.o: third_party/cares/cares/ares_expand_name.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_expand_name.o third_party/cares/cares/ares_expand_name.c

${OBJECTDIR}/third_party/cares/cares/ares_expand_string.o: third_party/cares/cares/ares_expand_string.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_expand_string.o third_party/cares/cares/ares_expand_string.c

${OBJECTDIR}/third_party/cares/cares/ares_fds.o: third_party/cares/cares/ares_fds.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_fds.o third_party/cares/cares/ares_fds.c

${OBJECTDIR}/third_party/cares/cares/ares_free_hostent.o: third_party/cares/cares/ares_free_hostent.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_free_hostent.o third_party/cares/cares/ares_free_hostent.c

${OBJECTDIR}/third_party/cares/cares/ares_free_string.o: third_party/cares/cares/ares_free_string.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_free_string.o third_party/cares/cares/ares_free_string.c

${OBJECTDIR}/third_party/cares/cares/ares_getenv.o: third_party/cares/cares/ares_getenv.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_getenv.o third_party/cares/cares/ares_getenv.c

${OBJECTDIR}/third_party/cares/cares/ares_gethostbyaddr.o: third_party/cares/cares/ares_gethostbyaddr.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_gethostbyaddr.o third_party/cares/cares/ares_gethostbyaddr.c

${OBJECTDIR}/third_party/cares/cares/ares_gethostbyname.o: third_party/cares/cares/ares_gethostbyname.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_gethostbyname.o third_party/cares/cares/ares_gethostbyname.c

${OBJECTDIR}/third_party/cares/cares/ares_getnameinfo.o: third_party/cares/cares/ares_getnameinfo.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_getnameinfo.o third_party/cares/cares/ares_getnameinfo.c

${OBJECTDIR}/third_party/cares/cares/ares_getopt.o: third_party/cares/cares/ares_getopt.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_getopt.o third_party/cares/cares/ares_getopt.c

${OBJECTDIR}/third_party/cares/cares/ares_getsock.o: third_party/cares/cares/ares_getsock.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_getsock.o third_party/cares/cares/ares_getsock.c

${OBJECTDIR}/third_party/cares/cares/ares_init.o: third_party/cares/cares/ares_init.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_init.o third_party/cares/cares/ares_init.c

${OBJECTDIR}/third_party/cares/cares/ares_library_init.o: third_party/cares/cares/ares_library_init.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_library_init.o third_party/cares/cares/ares_library_init.c

${OBJECTDIR}/third_party/cares/cares/ares_llist.o: third_party/cares/cares/ares_llist.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_llist.o third_party/cares/cares/ares_llist.c

${OBJECTDIR}/third_party/cares/cares/ares_mkquery.o: third_party/cares/cares/ares_mkquery.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_mkquery.o third_party/cares/cares/ares_mkquery.c

${OBJECTDIR}/third_party/cares/cares/ares_nowarn.o: third_party/cares/cares/ares_nowarn.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_nowarn.o third_party/cares/cares/ares_nowarn.c

${OBJECTDIR}/third_party/cares/cares/ares_options.o: third_party/cares/cares/ares_options.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_options.o third_party/cares/cares/ares_options.c

${OBJECTDIR}/third_party/cares/cares/ares_parse_a_reply.o: third_party/cares/cares/ares_parse_a_reply.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_parse_a_reply.o third_party/cares/cares/ares_parse_a_reply.c

${OBJECTDIR}/third_party/cares/cares/ares_parse_aaaa_reply.o: third_party/cares/cares/ares_parse_aaaa_reply.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_parse_aaaa_reply.o third_party/cares/cares/ares_parse_aaaa_reply.c

${OBJECTDIR}/third_party/cares/cares/ares_parse_mx_reply.o: third_party/cares/cares/ares_parse_mx_reply.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_parse_mx_reply.o third_party/cares/cares/ares_parse_mx_reply.c

${OBJECTDIR}/third_party/cares/cares/ares_parse_naptr_reply.o: third_party/cares/cares/ares_parse_naptr_reply.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_parse_naptr_reply.o third_party/cares/cares/ares_parse_naptr_reply.c

${OBJECTDIR}/third_party/cares/cares/ares_parse_ns_reply.o: third_party/cares/cares/ares_parse_ns_reply.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_parse_ns_reply.o third_party/cares/cares/ares_parse_ns_reply.c

${OBJECTDIR}/third_party/cares/cares/ares_parse_ptr_reply.o: third_party/cares/cares/ares_parse_ptr_reply.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_parse_ptr_reply.o third_party/cares/cares/ares_parse_ptr_reply.c

${OBJECTDIR}/third_party/cares/cares/ares_parse_soa_reply.o: third_party/cares/cares/ares_parse_soa_reply.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_parse_soa_reply.o third_party/cares/cares/ares_parse_soa_reply.c

${OBJECTDIR}/third_party/cares/cares/ares_parse_srv_reply.o: third_party/cares/cares/ares_parse_srv_reply.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_parse_srv_reply.o third_party/cares/cares/ares_parse_srv_reply.c

${OBJECTDIR}/third_party/cares/cares/ares_parse_txt_reply.o: third_party/cares/cares/ares_parse_txt_reply.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_parse_txt_reply.o third_party/cares/cares/ares_parse_txt_reply.c

${OBJECTDIR}/third_party/cares/cares/ares_platform.o: third_party/cares/cares/ares_platform.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_platform.o third_party/cares/cares/ares_platform.c

${OBJECTDIR}/third_party/cares/cares/ares_process.o: third_party/cares/cares/ares_process.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_process.o third_party/cares/cares/ares_process.c

${OBJECTDIR}/third_party/cares/cares/ares_query.o: third_party/cares/cares/ares_query.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_query.o third_party/cares/cares/ares_query.c

${OBJECTDIR}/third_party/cares/cares/ares_search.o: third_party/cares/cares/ares_search.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_search.o third_party/cares/cares/ares_search.c

${OBJECTDIR}/third_party/cares/cares/ares_send.o: third_party/cares/cares/ares_send.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_send.o third_party/cares/cares/ares_send.c

${OBJECTDIR}/third_party/cares/cares/ares_strcasecmp.o: third_party/cares/cares/ares_strcasecmp.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_strcasecmp.o third_party/cares/cares/ares_strcasecmp.c

${OBJECTDIR}/third_party/cares/cares/ares_strdup.o: third_party/cares/cares/ares_strdup.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_strdup.o third_party/cares/cares/ares_strdup.c

${OBJECTDIR}/third_party/cares/cares/ares_strerror.o: third_party/cares/cares/ares_strerror.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_strerror.o third_party/cares/cares/ares_strerror.c

${OBJECTDIR}/third_party/cares/cares/ares_timeout.o: third_party/cares/cares/ares_timeout.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_timeout.o third_party/cares/cares/ares_timeout.c

${OBJECTDIR}/third_party/cares/cares/ares_version.o: third_party/cares/cares/ares_version.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_version.o third_party/cares/cares/ares_version.c

${OBJECTDIR}/third_party/cares/cares/ares_writev.o: third_party/cares/cares/ares_writev.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/ares_writev.o third_party/cares/cares/ares_writev.c

${OBJECTDIR}/third_party/cares/cares/bitncmp.o: third_party/cares/cares/bitncmp.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/bitncmp.o third_party/cares/cares/bitncmp.c

${OBJECTDIR}/third_party/cares/cares/inet_net_pton.o: third_party/cares/cares/inet_net_pton.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/inet_net_pton.o third_party/cares/cares/inet_net_pton.c

${OBJECTDIR}/third_party/cares/cares/inet_ntop.o: third_party/cares/cares/inet_ntop.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/inet_ntop.o third_party/cares/cares/inet_ntop.c

${OBJECTDIR}/third_party/cares/cares/windows_port.o: third_party/cares/cares/windows_port.c
	${MKDIR} -p ${OBJECTDIR}/third_party/cares/cares
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/cares/cares/windows_port.o third_party/cares/cares/windows_port.c

${OBJECTDIR}/third_party/nanopb/pb_common.o: third_party/nanopb/pb_common.c
	${MKDIR} -p ${OBJECTDIR}/third_party/nanopb
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/nanopb/pb_common.o third_party/nanopb/pb_common.c

${OBJECTDIR}/third_party/nanopb/pb_decode.o: third_party/nanopb/pb_decode.c
	${MKDIR} -p ${OBJECTDIR}/third_party/nanopb
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/nanopb/pb_decode.o third_party/nanopb/pb_decode.c

${OBJECTDIR}/third_party/nanopb/pb_encode.o: third_party/nanopb/pb_encode.c
	${MKDIR} -p ${OBJECTDIR}/third_party/nanopb
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/nanopb/pb_encode.o third_party/nanopb/pb_encode.c

${OBJECTDIR}/third_party/zlib/adler32.o: third_party/zlib/adler32.c
	${MKDIR} -p ${OBJECTDIR}/third_party/zlib
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/zlib/adler32.o third_party/zlib/adler32.c

${OBJECTDIR}/third_party/zlib/compress.o: third_party/zlib/compress.c
	${MKDIR} -p ${OBJECTDIR}/third_party/zlib
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/zlib/compress.o third_party/zlib/compress.c

${OBJECTDIR}/third_party/zlib/crc32.o: third_party/zlib/crc32.c
	${MKDIR} -p ${OBJECTDIR}/third_party/zlib
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/zlib/crc32.o third_party/zlib/crc32.c

${OBJECTDIR}/third_party/zlib/deflate.o: third_party/zlib/deflate.c
	${MKDIR} -p ${OBJECTDIR}/third_party/zlib
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/zlib/deflate.o third_party/zlib/deflate.c

${OBJECTDIR}/third_party/zlib/gzclose.o: third_party/zlib/gzclose.c
	${MKDIR} -p ${OBJECTDIR}/third_party/zlib
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/zlib/gzclose.o third_party/zlib/gzclose.c

${OBJECTDIR}/third_party/zlib/gzlib.o: third_party/zlib/gzlib.c
	${MKDIR} -p ${OBJECTDIR}/third_party/zlib
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/zlib/gzlib.o third_party/zlib/gzlib.c

${OBJECTDIR}/third_party/zlib/gzread.o: third_party/zlib/gzread.c
	${MKDIR} -p ${OBJECTDIR}/third_party/zlib
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/zlib/gzread.o third_party/zlib/gzread.c

${OBJECTDIR}/third_party/zlib/gzwrite.o: third_party/zlib/gzwrite.c
	${MKDIR} -p ${OBJECTDIR}/third_party/zlib
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/zlib/gzwrite.o third_party/zlib/gzwrite.c

${OBJECTDIR}/third_party/zlib/infback.o: third_party/zlib/infback.c
	${MKDIR} -p ${OBJECTDIR}/third_party/zlib
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/zlib/infback.o third_party/zlib/infback.c

${OBJECTDIR}/third_party/zlib/inffast.o: third_party/zlib/inffast.c
	${MKDIR} -p ${OBJECTDIR}/third_party/zlib
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/zlib/inffast.o third_party/zlib/inffast.c

${OBJECTDIR}/third_party/zlib/inflate.o: third_party/zlib/inflate.c
	${MKDIR} -p ${OBJECTDIR}/third_party/zlib
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/zlib/inflate.o third_party/zlib/inflate.c

${OBJECTDIR}/third_party/zlib/inftrees.o: third_party/zlib/inftrees.c
	${MKDIR} -p ${OBJECTDIR}/third_party/zlib
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/zlib/inftrees.o third_party/zlib/inftrees.c

${OBJECTDIR}/third_party/zlib/trees.o: third_party/zlib/trees.c
	${MKDIR} -p ${OBJECTDIR}/third_party/zlib
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/zlib/trees.o third_party/zlib/trees.c

${OBJECTDIR}/third_party/zlib/uncompr.o: third_party/zlib/uncompr.c
	${MKDIR} -p ${OBJECTDIR}/third_party/zlib
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/zlib/uncompr.o third_party/zlib/uncompr.c

${OBJECTDIR}/third_party/zlib/zutil.o: third_party/zlib/zutil.c
	${MKDIR} -p ${OBJECTDIR}/third_party/zlib
	${RM} "$@.d"
	$(COMPILE.c) -g -DHAVE_CONFIG_H -DNOMINMAX -DOSATOMIC_USE_INLINED=1 -D_GNU_SOURCE -D_HAS_EXCEPTIONS -I. -Iinclude -Ithird_party/cares/cares -Ithird_party/cares -Ithird_party/cares/config_linux -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/third_party/zlib/zutil.o third_party/zlib/zutil.c

# Subprojects
.build-subprojects:

# Clean Targets
.clean-conf: ${CLEAN_SUBPROJECTS}
	${RM} -r ${CND_BUILDDIR}/${CND_CONF}

# Subprojects
.clean-subprojects:

# Enable dependency checking
.dep.inc: .depcheck-impl

include .dep.inc
