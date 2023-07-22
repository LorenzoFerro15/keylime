import asyncio
import os

from typing import Dict
from sqlalchemy.exc import SQLAlchemyError


from keylime import keylime_logging, config, cloud_verifier_common, tornado_requests, json
from keylime.crypto import rsa_import_pubkey, rsa_verify
from keylime.db.verifier_db import VerfierMain

logger = keylime_logging.init_logging("client_verifier")

GLOBAL_POLICY_CACHE: Dict[str, Dict[str, str]] = {}

async def validate_list(ns_golden_values: str, cloud_verifier, container_id) -> bool:
    
    params = cloud_verifier_common.prepare_get_quote(cloud_verifier)

    kwargs = {}
    if cloud_verifier["ssl_context"]:
        kwargs["context"] = cloud_verifier["ssl_context"]
   
    res = tornado_requests.request(
        "GET",
        f"http://{cloud_verifier['ip']}:{cloud_verifier['port']}/v{cloud_verifier['supported_version']}/container/{container_id}"
        f"?nonce={params['nonce']}&mask={params['mask']}"
        f"&partial={0}&ima_ml_entry={params['ima_ml_entry']}",
        **kwargs
    )

    response = await res

    if response.status_code != 200:
        logger.critical(
            "Unexpected Get Quote response error for cloud agent %s, Error: %s",
            container_id,
            response.status_code,
        )
        return False
    json_response = json.loads(response.body)

    ns_ima_mes_list = json_response["measurement_list"]
    signature = json_response["signature"]
    public_key = rsa_import_pubkey(json_response["public_key"])

    ver_result = rsa_verify(public_key, ns_ima_mes_list, signature)

    if ver_result == False:
        # failure in signature verification
        logger.critical(
            "signatue of the namespace list verification failure on agent: %s",
            container_id
        )
        return False

    ns_ima_mes_list = ns_ima_mes_list.decode('UTF-8').split('\n')

    for linenum, line in enumerate(ns_ima_mes_list):
        if(line != ""):
            gold_line_tokens = ns_golden_values[linenum].split(" ")
            line_tokens = line.split(" ")
            if(gold_line_tokens[2] != line_tokens[2]):
                return False
            
            if(gold_line_tokens[3] != line_tokens[3] or gold_line_tokens[4] != line_tokens[4] or gold_line_tokens[5] != line_tokens[5]):
                return False
    return True

def main() -> None:

    namespace_id = 2

    config.check_version("clientverifier", logger=logger)

    cloud_verifier = {
        "port": config.get("clientverifier", "cloud_verifier_port"),
        "ip": config.get("clientverifier", "cloud_verifier_ip"),
        "uuid": cloud_verifier_common.DEFAULT_VERIFIER_ID
    }

    os.umask(0o077)


    try:
        loop = asyncio.get_event_loop()
        res = loop.run_until_complete(validate_list(cloud_verifier, VerfierMain.agent_id, namespace_id))
        
        if res:
            print("container list successfully verified")
        else:
            print("error verifing the list")
        

    except SQLAlchemyError as e:
        logger.error("SQLAlchemy Error: %s", e)