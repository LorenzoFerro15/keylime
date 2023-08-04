import asyncio
import base64
import functools
import os
import signal
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Process
from typing import Any, Dict, List, Optional, Tuple, Union, cast

import tornado.httpserver
import tornado.ioloop
import tornado.netutil
import tornado.process
import tornado.web
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, joinedload
from sqlalchemy.orm.exc import NoResultFound  # pyright: ignore

from keylime import api_version as keylime_api_version
from keylime import (
    cloud_verifier_common,
    cloud_verifier_tornado,
    config,
    json,
    keylime_logging,
    revocation_notifier,
    signing,
    tornado_requests,
    web_util,
)
from keylime.agentstates import AgentAttestState, AgentAttestStates
from keylime.common import retry, states, validators
from keylime.da import record
from keylime.db.keylime_db import DBEngineManager, SessionManager
from keylime.db.verifier_db import VerfierMain, VerifierAllowlist
from keylime.failure import MAX_SEVERITY_LABEL, Component, Event, Failure, set_severity_config
from keylime.ima import ima

logger = keylime_logging.init_logging("verifier")

set_severity_config(config.getlist("verifier", "severity_labels"), config.getlist("verifier", "severity_policy"))

try:
    engine = DBEngineManager().make_engine("cloud_verifier")
except SQLAlchemyError as err:
    logger.error("Error creating SQL engine or session: %s", err)
    sys.exit(1)


def get_session() -> Session:
    return SessionManager().make_session(engine)

try:
    rmc = record.get_record_mgt_class(config.get("registrar", "durable_attestation_import", fallback=""))
    if rmc:
        rmc = rmc("verifier")
except record.RecordManagementException as rme:
    logger.error("Error initializing Durable Attestation: %s", rme)
    sys.exit(1)

def get_AgentAttestStates() -> AgentAttestStates:
    return AgentAttestStates.get_instance()

async def invoke_get_quote(
    agent: Dict[str, Any], runtime_policy: str, need_pubkey: bool, timeout: float = 60.0
) -> None:
    failure = Failure(Component.INTERNAL, ["verifier"])

    params = cloud_verifier_common.prepare_get_quote(agent)

    partial_req = "1"
    if need_pubkey:
        partial_req = "0"

    # TODO: remove special handling after initial upgrade
    kwargs = {}
    if agent["ssl_context"]:
        kwargs["context"] = agent["ssl_context"]

    res = tornado_requests.request(
        "GET",
        f"http://{agent['ip']}:{agent['port']}/v{agent['supported_version']}/quotes/container"
        f"?nonce={params['nonce']}&mask={params['mask']}"
        f"&partial={partial_req}&ima_ml_entry={params['ima_ml_entry']}&containerid=432432",
        **kwargs,
        timeout=timeout,
    )
    response = await res

    if response.status_code != 200:
        # this is a connection error, retry get quote
        if response.status_code in [408, 500, 599]:
            asyncio.ensure_future(cloud_verifier_tornado.process_agent(agent, states.GET_QUOTE_RETRY))
        else:
            # catastrophic error, do not continue
            logger.critical(
                "Unexpected Get Quote response error for cloud agent %s, Error: %s",
                agent["agent_id"],
                response.status_code,
            )
            failure.add_event("no_quote", "Unexpected Get Quote reponse from agent", False)
            asyncio.ensure_future(cloud_verifier_tornado.process_agent(agent, states.FAILED, failure))
    else:
        try:
            json_response = json.loads(response.body)

            # validate the cloud agent response
            if "provide_V" not in agent:
                agent["provide_V"] = True
            agentAttestState = get_AgentAttestStates().get_by_agent_id(agent["agent_id"])

            if rmc:
                rmc.record_create(agent, json_response, runtime_policy)

            failure = cloud_verifier_common.process_quote_response(
                agent,
                ima.deserialize_runtime_policy(runtime_policy),
                json_response["results"],
                agentAttestState,
            )
            if not failure:
                if agent["provide_V"]:
                    asyncio.ensure_future(cloud_verifier_tornado.process_agent(agent, states.PROVIDE_V))
                else:
                    asyncio.ensure_future(cloud_verifier_tornado.process_agent(agent, states.GET_QUOTE))
            else:
                asyncio.ensure_future(cloud_verifier_tornado.process_agent(agent, states.INVALID_QUOTE, failure))

            # store the attestation state
            cloud_verifier_tornado.store_attestation_state(agentAttestState)

        except Exception as e:
            logger.exception(e)
            failure.add_event(
                "exception", {"context": "Agent caused the verifier to throw an exception", "data": str(e)}, False
            )
            asyncio.ensure_future(cloud_verifier_tornado.process_agent(agent, states.FAILED, failure))


def main() -> None:
    """Main method of the Cloud Verifier Server.  This method is encapsulated in a function for packaging to allow it to be
    called as a function by an external program."""

    config.check_version("verifier", logger=logger)

    verifier_port = config.get("verifier", "port")
    verifier_host = config.get("verifier", "ip")
    verifier_id = config.get("verifier", "uuid", fallback=cloud_verifier_common.DEFAULT_VERIFIER_ID)

    # set a conservative general umask
    os.umask(0o077)

    VerfierMain.metadata.create_all(engine, checkfirst=True)
    session = get_session()
    try:
        query_all = session.query(VerfierMain).all()
        for row in query_all:
            if row.operational_state in states.APPROVED_REACTIVATE_STATES:
                row.operational_state = states.START  # pyright: ignore
        session.commit()
    except SQLAlchemyError as e:
        logger.error("SQLAlchemy Error: %s", e)

    # print out API versions we support
    keylime_api_version.log_api_versions(logger)

    processes: List[Process] = []

    run_revocation_notifier = "zeromq" in revocation_notifier.get_notifiers()

    def sig_handler(*_: Any) -> None:
        if run_revocation_notifier:
            revocation_notifier.stop_broker()
        for p in processes:
            p.join()
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)
    if run_revocation_notifier:
        logger.info(
            "Starting service for revocation notifications on port %s",
            config.getint("verifier", "zmq_port", section="revocations"),
        )
        revocation_notifier.start_broker()

    num_workers = config.getint("verifier", "num_workers")
    if num_workers <= 0:
        num_workers = tornado.process.cpu_count()

    agents = cloud_verifier_tornado.get_agents_by_verifier_id(verifier_id)
    for task_id in range(0, num_workers):
        active_agents = [agents[i] for i in range(task_id, len(agents), num_workers)]
        process = Process(target=cloud_verifier_tornado.server_process, args=(task_id, active_agents))
        process.start()
        processes.append(process)
