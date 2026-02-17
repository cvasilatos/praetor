import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar, cast


class ColorFormatter(logging.Formatter):
    cyan, blue, gray, yellow, red, bold_red = (
        "\x1b[36m",
        "\x1b[34m",
        "\x1b[37m",
        "\x1b[33m",
        "\x1b[31m",
        "\x1b[31;1m",
    )
    reset = "\x1b[0m"
    fmt_str = "%(asctime)s - [%(levelname)s] - %(name).10s - %(message)s"

    def format(self, record: logging.LogRecord) -> str:

        formats = {
            5: f"{self.cyan}{self.fmt_str}{self.reset}",
            logging.DEBUG: f"{self.blue}{self.fmt_str}{self.reset}",
            logging.INFO: f"{self.gray}{self.fmt_str}{self.reset}",
            logging.WARNING: f"{self.yellow}{self.fmt_str}{self.reset}",
            logging.ERROR: f"{self.red}{self.fmt_str}{self.reset}",
            logging.CRITICAL: f"{self.bold_red}{self.fmt_str}{self.reset}",
        }
        log_fmt = formats.get(record.levelno, self.fmt_str)

        return logging.Formatter(log_fmt).format(record)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_record: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=datetime.now().astimezone().tzinfo
            ).isoformat(),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
        }
        # If the user passed extra={} data, include it
        if hasattr(record, "extra_data"):
            log_record["extra"] = getattr(record, "extra_data", None)

        return json.dumps(log_record)


class CustomLogger(logging.Logger):
    TRACE: ClassVar[int] = 5
    logging.addLevelName(TRACE, "TRACE")

    def trace(self, msg: str, *args: Any, **kwargs: Any) -> None:
        if self.isEnabledFor(self.TRACE):
            self._log(self.TRACE, msg, args, **kwargs)

    @staticmethod
    def setup_logging(folder: str, filename: str, level: str) -> None:
        logging.setLoggerClass(CustomLogger)

        root = logging.getLogger()
        for handler in root.handlers[:]:
            root.removeHandler(handler)

        log_dir = Path(folder)
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_dir / f"{filename}.log", mode="w")
        file_handler.setFormatter(logging.Formatter(ColorFormatter.fmt_str))

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(ColorFormatter())

        log_path = Path(folder) / f"{filename}.jsonl"
        file_h = logging.FileHandler(log_path, mode="a")
        file_h.setFormatter(JsonFormatter())

        logging.basicConfig(
            level=level, handlers=[console_handler, file_handler, file_h]
        )


if __name__ == "__main__":
    CustomLogger.setup_logging("logs", "protocol_validator", level="TRACE")

    logger = cast("CustomLogger", logging.getLogger("MainApp"))

    logger.trace("This should be CYAN!")
    logger.info("This should be GRAY!")
    logger.error("This should be RED!")
