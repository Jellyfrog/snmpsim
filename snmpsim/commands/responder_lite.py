# This file is part of snmpsim software.
#
# Copyright (c) 2010-2019, Ilya Etingof <etingof@gmail.com>
# Copyright (c) 2022-2025, LeXtudio Inc. <support@lextudio.com>
# License: https://www.pysnmp.com/snmpsim/license.html
#
# SNMP Agent Simulator: lightweight SNMP v1/v2c command responder
#
import argparse
import asyncio
import functools
import os
import socket
import sys
import traceback

from pyasn1 import debug as pyasn1_debug
from pyasn1.codec.ber import decoder
from pyasn1.codec.ber import encoder
from pyasn1.type import univ
from pysnmp import debug as pysnmp_debug
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.carrier.asyncio.dgram import udp6
from pysnmp.proto import api
from pysnmp.proto import rfc1902
from pysnmp.proto import rfc1905

from snmpsim import confdir
from snmpsim import controller
from snmpsim import daemon
from snmpsim import datafile
from snmpsim import endpoints
from snmpsim import fastber
from snmpsim import log
from snmpsim import utils
from snmpsim import variation
from snmpsim.error import NoDataNotification
from snmpsim.error import SnmpsimError
from snmpsim.reporting.manager import ReportingManager

SET_REQUEST = 0xA3

# fairness between endpoints under load
MAX_MESSAGES_PER_WAKEUP = 64

NULL = univ.Null("")

SNMP_2TO1_ERROR_MAP = {
    rfc1902.Counter64.tagSet: 5,
    rfc1905.NoSuchObject.tagSet: 2,
    rfc1905.NoSuchInstance.tagSet: 2,
    rfc1905.EndOfMibView.tagSet: 2,
}

DESCRIPTION = (
    "Lightweight SNMP agent simulator: responds to SNMP v1/v2c requests, "
    "variate responses based on transport addresses, SNMP community name "
    "or via variation modules."
)


def main():
    # Python 3.14+ no longer auto-creates a default event loop.
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())

    parser = argparse.ArgumentParser(description=DESCRIPTION)

    parser.add_argument("-v", "--version", action="version", version=utils.TITLE)

    parser.add_argument(
        "--quiet", action="store_true", help="Do not print out informational messages"
    )

    parser.add_argument(
        "--debug",
        choices=pysnmp_debug.flagMap,
        action="append",
        type=str,
        default=[],
        help="Enable one or more categories of SNMP debugging.",
    )

    parser.add_argument(
        "--debug-asn1",
        choices=pyasn1_debug.FLAG_MAP,
        action="append",
        type=str,
        default=[],
        help="Enable one or more categories of ASN.1 debugging.",
    )

    parser.add_argument(
        "--logging-method",
        type=lambda x: x.split(":"),
        metavar="=<%s[:args]>]" % "|".join(log.METHODS_MAP),
        default="stderr",
        help="Logging method.",
    )

    parser.add_argument(
        "--log-level",
        choices=log.LEVELS_MAP,
        type=str,
        default="info",
        help="Logging level.",
    )

    parser.add_argument(
        "--reporting-method",
        type=lambda x: x.split(":"),
        metavar="=<%s[:args]>]" % "|".join(ReportingManager.REPORTERS),
        default="null",
        help="Activity metrics reporting method.",
    )

    parser.add_argument(
        "--daemonize",
        action="store_true",
        help="Disengage from controlling terminal and become a daemon",
    )

    parser.add_argument(
        "--process-user",
        type=str,
        help="If run as root, switch simulator daemon to this user right "
        "upon binding privileged ports",
    )

    parser.add_argument(
        "--process-group",
        type=str,
        help="If run as root, switch simulator daemon to this group right "
        "upon binding privileged ports",
    )

    parser.add_argument(
        "--pid-file",
        metavar="<FILE>",
        type=str,
        default=f"/var/run/{__name__}/{os.getpid()}.pid",
        help="SNMP simulation data file to write records to",
    )

    parser.add_argument(
        "--cache-dir",
        metavar="<DIR>",
        type=str,
        help="Location for SNMP simulation data file indices to create",
    )

    parser.add_argument(
        "--force-index-rebuild",
        action="store_true",
        help="Rebuild simulation data files indices even if they seem up to date",
    )

    parser.add_argument(
        "--validate-data",
        action="store_true",
        help="Validate simulation data files on daemon start-up",
    )

    parser.add_argument(
        "--variation-modules-dir",
        metavar="<DIR>",
        type=str,
        action="append",
        default=[],
        help="Variation modules search path(s)",
    )

    parser.add_argument(
        "--variation-module-options",
        metavar="<module[=alias][:args]>",
        type=str,
        action="append",
        default=[],
        help="Options for a specific variation module",
    )

    parser.add_argument(
        "--v2c-arch",
        action="store_true",
        help="Use lightweight, legacy SNMP architecture capable to support "
        "v1/v2c versions of SNMP",
    )

    parser.add_argument(
        "--v3-only",
        action="store_true",
        help="Trip legacy SNMP v1/v2c support to gain a little lesser memory footprint",
    )

    parser.add_argument(
        "--transport-id-offset",
        type=int,
        default=0,
        help="Start numbering the last sub-OID of transport endpoint OIDs "
        "starting from this ID",
    )

    parser.add_argument(
        "--max-var-binds",
        type=int,
        default=64,
        help="Maximum number of variable bindings to include in a single response",
    )

    parser.add_argument(
        "--data-dir",
        type=str,
        action="append",
        metavar="<DIR>",
        dest="data_dirs",
        help="SNMP simulation data recordings directory.",
    )

    endpoint_group = parser.add_mutually_exclusive_group(required=True)

    endpoint_group.add_argument(
        "--agent-udpv4-endpoint",
        type=str,
        action="append",
        metavar="<[X.X.X.X]:NNNNN>",
        dest="agent_udpv4_endpoints",
        default=[],
        help="SNMP agent UDP/IPv4 address to listen on (name:port)",
    )

    endpoint_group.add_argument(
        "--agent-udpv6-endpoint",
        type=str,
        action="append",
        metavar="<[X:X:..X]:NNNNN>",
        dest="agent_udpv6_endpoints",
        default=[],
        help="SNMP agent UDP/IPv6 address to listen on ([name]:port)",
    )

    args = parser.parse_args()

    if args.debug:
        pysnmp_debug.setLogger(pysnmp_debug.Debug(*args.debug))

    if args.debug_asn1:
        pyasn1_debug.setLogger(pyasn1_debug.Debug(*args.debug_asn1))

    if args.cache_dir:
        confdir.cache = args.cache_dir

    if args.variation_modules_dir:
        confdir.variation = args.variation_modules_dir

    variation_modules_options = variation.parse_modules_options(
        args.variation_module_options
    )

    with daemon.PrivilegesOf(args.process_user, args.process_group):
        proc_name = os.path.basename(sys.argv[0])

        try:
            log.set_logger(proc_name, *args.logging_method, force=True)

            if args.log_level:
                log.set_level(args.log_level)

        except SnmpsimError as exc:
            sys.stderr.write("%s\r\n" % exc)
            parser.print_usage(sys.stderr)
            return 1

        try:
            ReportingManager.configure(*args.reporting_method)

        except SnmpsimError as exc:
            sys.stderr.write("%s\r\n" % exc)
            parser.print_usage(sys.stderr)
            return 1

    if args.daemonize:
        try:
            daemon.daemonize(args.pid_file)

        except Exception as exc:
            sys.stderr.write("ERROR: cant daemonize process: %s\r\n" % exc)
            parser.print_usage(sys.stderr)
            return 1

    if not os.path.exists(confdir.cache):
        try:
            with daemon.PrivilegesOf(args.process_user, args.process_group):
                os.makedirs(confdir.cache)

        except OSError as exc:
            log.error(
                'failed to create cache directory "%s": %s' % (confdir.cache, exc)
            )
            return 1

        else:
            log.info('Cache directory "%s" created' % confdir.cache)

    variation_modules = variation.load_variation_modules(
        confdir.variation, variation_modules_options
    )

    with daemon.PrivilegesOf(args.process_user, args.process_group):
        variation.initialize_variation_modules(variation_modules, mode="variating")

    def configure_managed_objects(
        data_dirs, data_index_instrum_controller, snmp_engine=None, snmp_context=None
    ):
        """Build pysnmp Managed Objects base from data files information"""

        _mib_instrums = {}
        _data_files = {}

        data_files = {
            data_dir: datafile.get_data_files(data_dir)
            for data_dir in data_dirs
            if os.path.exists(data_dir)
        }

        indexed = datafile.build_indices(
            [data_file for files in data_files.values() for data_file in files],
            args.force_index_rebuild,
            args.validate_data,
        )

        for dataDir in data_dirs:
            log.info(
                'Scanning "%s" directory for %s data '
                "files..."
                % (
                    dataDir,
                    ",".join(
                        [
                            f" *{os.path.extsep}{x.ext}"
                            for x in variation.RECORD_TYPES.values()
                        ]
                    ),
                )
            )

            if not os.path.exists(dataDir):
                log.info('Directory "%s" does not exist' % dataDir)
                continue

            log.msg.inc_ident()

            for full_path, text_parser, community_name in data_files[dataDir]:
                if community_name in _data_files:
                    log.error(
                        'ignoring duplicate Community/ContextName "%s" for data '
                        "file %s (%s already loaded)"
                        % (community_name, full_path, _data_files[community_name])
                    )
                    continue

                elif full_path in _mib_instrums:
                    mib_instrum = _mib_instrums[full_path]
                    log.info(f"Configuring *shared* {mib_instrum}")

                else:
                    data_file = datafile.DataFile(
                        full_path, text_parser, variation_modules
                    )
                    data_file.index_text(
                        args.force_index_rebuild and full_path not in indexed,
                        args.validate_data,
                    )

                    MibController = controller.MIB_CONTROLLERS[data_file.layout]
                    mib_instrum = MibController(data_file)

                    _mib_instrums[full_path] = mib_instrum
                    _data_files[community_name] = full_path

                    log.info(f"Configuring {mib_instrum}")

                log.info(f"SNMPv1/2c community name: {community_name}")

                contexts[univ.OctetString(community_name)] = mib_instrum

                data_index_instrum_controller.add_data_file(full_path, community_name)

            log.msg.dec_ident()

        del _mib_instrums
        del _data_files

    def get_bulk_handler(
        req_var_binds, non_repeaters, max_repetitions, read_next_vars, read_next_run=None
    ):
        """Only v2c arch GETBULK handler"""
        N = min(int(non_repeaters), len(req_var_binds))
        M = int(max_repetitions)
        R = max(len(req_var_binds) - N, 0)

        if R:
            M = min(M, int(args.max_var_binds / R))

        if N:
            rsp_var_binds = read_next_vars(*req_var_binds[:N])

        else:
            rsp_var_binds = []

        var_binds = req_var_binds[-R:]

        if R == 1 and M > 0 and read_next_run:
            # a single column is a chain of GETNEXTs, done in one go
            rsp_var_binds.extend(read_next_run(var_binds[0], M))
            return rsp_var_binds

        while M and R:
            rsp_var_binds.extend(read_next_vars(*var_binds))
            var_binds = rsp_var_binds[-R:]
            M -= 1

        return rsp_var_binds

    @functools.lru_cache(maxsize=4096)
    def select_context(transport_domain, source_address, community_name):
        """Pick data file context, these do not change after start-up"""
        for candidate in datafile.probe_context(
            transport_domain,
            (source_address,),
            context_engine_id=datafile.SELF_LABEL,
            context_name=univ.OctetString(community_name),
        ):
            if candidate in contexts:
                return candidate

    def process_request(
        msg_ver,
        community_name,
        pdu_type,
        req_var_binds,
        non_repeaters,
        max_repetitions,
        transport_domain,
        transport_address,
    ):
        """Run request against the selected data file.

        Returns (error_status, error_index, var_binds) of the response or
        None when no response should be sent.
        """
        candidate = select_context(
            tuple(transport_domain), transport_address[0], community_name
        )

        if candidate is None:
            log.error(
                "No data file selected for transport ID %s, source "
                "address %s, community name "
                '"%s"'
                % (
                    univ.ObjectIdentifier(transport_domain),
                    transport_address[0],
                    community_name.decode("iso-8859-1"),
                )
            )
            return

        if log.enabled(log.LOG_INFO):
            log.info(
                "Using %s selected by candidate %s; transport ID %s, "
                "source address %s, context engine ID <empty>, "
                "community name "
                '"%s"'
                % (
                    contexts[candidate],
                    candidate,
                    univ.ObjectIdentifier(transport_domain),
                    transport_address[0],
                    community_name.decode("iso-8859-1"),
                )
            )

        mib_instrum = contexts[candidate]

        if pdu_type == fastber.GET_REQUEST:
            backend_fun = mib_instrum.read_variables

        elif pdu_type == SET_REQUEST:
            backend_fun = mib_instrum.write_variables

        elif pdu_type == fastber.GET_NEXT_REQUEST:
            backend_fun = mib_instrum.read_next_variables

        else:  # GETBULK
            if not msg_ver:
                log.info(
                    "GETBULK over SNMPv1 from %s:%s"
                    % (transport_domain, transport_address)
                )
                return

            def backend_fun(*var_binds):
                return get_bulk_handler(
                    var_binds,
                    non_repeaters,
                    max_repetitions,
                    mib_instrum.read_next_variables,
                    getattr(mib_instrum, "read_next_run", None),
                )

        try:
            var_binds = backend_fun(*req_var_binds)

        except NoDataNotification:
            return

        except Exception as exc:
            log.error("Ignoring SNMP engine failure: %s" % exc)
            return

        if not msg_ver:
            for idx, (oid, val) in enumerate(var_binds):
                if val.tagSet in SNMP_2TO1_ERROR_MAP:
                    return SNMP_2TO1_ERROR_MAP[val.tagSet], idx + 1, req_var_binds

        return 0, 0, var_binds

    def fast_command_responder(transport_domain, transport_address, whole_msg):
        """Handle common requests without pyasn1 message (de)serialization.

        Returns the encoded response, None if no response should be sent
        or raises fastber.Unsupported if the message is not handled.
        """
        (
            msg_ver,
            community_name,
            pdu_type,
            request_id,
            non_repeaters,
            max_repetitions,
            oids,
        ) = fastber.decode_request(whole_msg)

        req_var_binds = [(univ.ObjectIdentifier(oid), NULL) for oid in oids]

        response = process_request(
            msg_ver,
            community_name,
            pdu_type,
            req_var_binds,
            non_repeaters,
            max_repetitions,
            transport_domain,
            transport_address,
        )

        if response is None:
            return

        error_status, error_index, var_binds = response

        try:
            return fastber.encode_response(
                msg_ver,
                community_name,
                request_id,
                error_status,
                error_index,
                var_binds,
            )

        except Exception:
            # unusual response contents, let pysnmp encode it
            p_mod = api.PROTOCOL_MODULES[msg_ver]

            rsp_msg = p_mod.Message()
            p_mod.apiMessage.set_defaults(rsp_msg)
            p_mod.apiMessage.set_version(rsp_msg, msg_ver)
            p_mod.apiMessage.set_community(rsp_msg, community_name)

            rsp_pdu = p_mod.GetResponsePDU()
            p_mod.apiPDU.set_defaults(rsp_pdu)
            p_mod.apiPDU.set_request_id(rsp_pdu, request_id)
            p_mod.apiPDU.set_error_status(rsp_pdu, error_status)
            p_mod.apiPDU.set_error_index(rsp_pdu, error_index)
            p_mod.apiPDU.set_varbinds(rsp_pdu, var_binds)

            p_mod.apiMessage.set_pdu(rsp_msg, rsp_pdu)

            return encoder.encode(rsp_msg)

    def handle_message(send, transport_domain, transport_address, whole_msg):
        """v2c arch command responder request handling"""
        try:
            rsp = fast_command_responder(transport_domain, transport_address, whole_msg)

        except fastber.Unsupported:
            pass

        else:
            if rsp is not None:
                send(rsp)

            return

        while whole_msg:
            msg_ver = api.decodeMessageVersion(whole_msg)

            if msg_ver in api.PROTOCOL_MODULES:
                p_mod = api.PROTOCOL_MODULES[msg_ver]

            else:
                log.error(f"Unsupported SNMP version {msg_ver}")
                return

            req_msg, whole_msg = decoder.decode(whole_msg, asn1Spec=p_mod.Message())

            req_pdu = p_mod.apiMessage.get_pdu(req_msg)

            if req_pdu.isSameTypeWith(p_mod.GetRequestPDU()):
                pdu_type = fastber.GET_REQUEST

            elif req_pdu.isSameTypeWith(p_mod.SetRequestPDU()):
                pdu_type = SET_REQUEST

            elif req_pdu.isSameTypeWith(p_mod.GetNextRequestPDU()):
                pdu_type = fastber.GET_NEXT_REQUEST

            elif hasattr(p_mod, "GetBulkRequestPDU") and req_pdu.isSameTypeWith(
                p_mod.GetBulkRequestPDU()
            ):
                pdu_type = fastber.GET_BULK_REQUEST

            else:
                log.error(
                    "Unsupported PDU type %s from "
                    "%s:%s"
                    % (req_pdu.__class__.__name__, transport_domain, transport_address)
                )
                return whole_msg

            if pdu_type == fastber.GET_BULK_REQUEST and msg_ver:
                non_repeaters = p_mod.apiBulkPDU.get_non_repeaters(req_pdu)
                max_repetitions = p_mod.apiBulkPDU.get_max_repetitions(req_pdu)

            else:
                non_repeaters = max_repetitions = None

            response = process_request(
                msg_ver,
                req_msg.getComponentByPosition(1).asOctets(),
                pdu_type,
                p_mod.apiPDU.get_varbinds(req_pdu),
                non_repeaters,
                max_repetitions,
                transport_domain,
                transport_address,
            )

            if response is None:
                return whole_msg

            error_status, error_index, var_binds = response

            rsp_msg = p_mod.apiMessage.get_response(req_msg)
            rsp_pdu = p_mod.apiMessage.get_pdu(rsp_msg)

            if error_status:
                p_mod.apiPDU.set_error_status(rsp_pdu, error_status)
                p_mod.apiPDU.set_error_index(rsp_pdu, error_index)

            p_mod.apiPDU.set_varbinds(rsp_pdu, var_binds)

            send(encoder.encode(rsp_msg))

        return whole_msg

    def receive(sock, transport_domain):
        """Read and answer pending requests on a server socket"""
        for _ in range(MAX_MESSAGES_PER_WAKEUP):
            try:
                whole_msg, transport_address = sock.recvfrom(65535)

            except (BlockingIOError, InterruptedError):
                return

            except OSError as exc:
                log.error("Failed to receive on %s: %s" % (sock.getsockname(), exc))
                return

            def send(data):
                try:
                    sock.sendto(data, transport_address)

                except OSError as exc:
                    log.error(
                        "Failed to send response to %s: %s" % (transport_address, exc)
                    )

            try:
                handle_message(send, transport_domain, transport_address, whole_msg)

            except Exception as exc:
                log.error("Ignoring request from %s: %s" % (transport_address[0], exc))

    # Configure access to data index

    log.info(
        "Maximum number of variable bindings in SNMP response: %s" % args.max_var_binds
    )

    data_index_instrum_controller = controller.DataIndexInstrumController()

    contexts = {univ.OctetString("index"): data_index_instrum_controller}

    with daemon.PrivilegesOf(args.process_user, args.process_group):
        configure_managed_objects(
            args.data_dirs or confdir.data, data_index_instrum_controller
        )

    contexts["index"] = data_index_instrum_controller

    # Configure socket server
    loop = asyncio.get_event_loop()

    server_sockets = []

    def open_server_socket(endpoint, transport_domain, ipv6=False):
        address = endpoints.parse_endpoint(endpoint, ipv6=ipv6)

        sock = socket.socket(
            socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_DGRAM
        )

        try:
            sock.bind(address)

        except OSError as exc:
            sock.close()
            raise SnmpsimError(f"Failed to bind UDP endpoint {endpoint}: {exc}")

        sock.setblocking(False)

        loop.add_reader(sock, receive, sock, transport_domain)

        server_sockets.append(sock)

        log.msg(
            "Listening at UDP/IPv%s endpoint %s, transport ID "
            "%s"
            % (
                ipv6 and 6 or 4,
                endpoint,
                ".".join([str(handler) for handler in transport_domain]),
            )
        )

    transport_index = args.transport_id_offset

    for agent_udpv4_endpoint in args.agent_udpv4_endpoints:
        transport_domain = udp.DOMAIN_NAME + (transport_index,)
        transport_index += 1

        open_server_socket(agent_udpv4_endpoint, transport_domain)

    transport_index = args.transport_id_offset

    for agent_udpv6_endpoint in args.agent_udpv6_endpoints:
        transport_domain = udp6.DOMAIN_NAME + (transport_index,)
        transport_index += 1

        open_server_socket(agent_udpv6_endpoint, transport_domain, ipv6=True)

    with daemon.PrivilegesOf(args.process_user, args.process_group, final=True):
        try:
            loop.run_forever()

        except KeyboardInterrupt:
            log.info("Shutting down process...")

        finally:
            if variation_modules:
                log.info("Shutting down variation modules:")

                for name, contexts in variation_modules.items():
                    body = contexts[0]
                    try:
                        body["shutdown"](options=body["args"], mode="variation")

                    except Exception as exc:
                        log.error(
                            'Variation module "%s" shutdown FAILED: %s' % (name, exc)
                        )

                    else:
                        log.info('Variation module "%s" shutdown OK' % name)

            for sock in server_sockets:
                loop.remove_reader(sock)
                sock.close()

            log.info("Process terminated")

    return 0


if __name__ == "__main__":
    try:
        rc = main()

    except KeyboardInterrupt:
        sys.stderr.write("shutting down process...")
        rc = 0

    except Exception as exc:
        sys.stderr.write("process terminated: %s" % exc)

        for line in traceback.format_exception(*sys.exc_info()):
            sys.stderr.write(line.replace("\n", ";"))
        rc = 1

    sys.exit(rc)
