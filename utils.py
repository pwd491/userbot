from re import findall
from typing import Set
from pathlib import Path


def extract_hashtags(text: str) -> Set[str]:
    return set(findall(r"#\w+", text.lower()))


def prompt_to_text(tags: set, columns: int = 3) -> str:
    header = "🍀**Навигация по хештегам**🍀"
    sorted_tags = sorted(tags)
    body = " ".join(sorted_tags)
    return f"{header}\n\n**{body}**"


def get_session_file(name: str, return_as_abs_url: bool = False) -> Path:
    for file in Path("sessions").iterdir():
        if file.is_file() and file.stem == name and file.suffix == ".session":
            return file.absolute() if return_as_abs_url else file
    raise FileNotFoundError(f"{name} doesn't exists.")
