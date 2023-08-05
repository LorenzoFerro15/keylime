from keylime import cloud_verifier_tornado, config, keylime_logging
from keylime.common.migrations import apply
import sys

logger = keylime_logging.init_logging("verifier")


def usage() -> None:
    print("Please pass the container identifier to attest")
    sys.exit(-1)


def main() -> None:
    if len(sys.argv) < 2:
        usage()
    container_identifier = sys.argv[1]
    
    if config.has_option("verifier", "auto_migrate_db") and config.getboolean("verifier", "auto_migrate_db"):
        apply("cloud_verifier")

    cloud_verifier_tornado.main(container_id=int(container_identifier))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)
