from keylime import contein_verification, config, keylime_logging
from keylime.common.migrations import apply
from keylime.mba import mba

logger = keylime_logging.init_logging("verifier")


def main() -> None:
    # if we are configured to auto-migrate the DB, check if there are any migrations to perform
    if config.has_option("verifier", "auto_migrate_db") and config.getboolean("verifier", "auto_migrate_db"):
        apply("cloud_verifier")

    # Load explicitly the policy modules into Keylime for the verifier,
    # so that they are not loaded accidentally from other components
    contein_verification.main()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)
