from re import findall
from typing import Set, Optional
from pathlib import Path
from urllib.parse import urlparse


def extract_hashtags(text: str) -> Set[str]:
    return set(findall(r"#\w+", text.lower()))


def prompt_to_text(tags: set) -> str:
    header = "🍀**Навигация по хештегам**🍀"
    sorted_tags = sorted(tags)
    body = " ".join(sorted_tags)
    return f"{header}\n\n**{body}**"


def get_session_file(name: str, return_as_abs_url: bool = False) -> Path:
    for file in Path("/opt/userbot/sessions").iterdir():
        if file.is_file() and file.stem == name and file.suffix == ".session":
            return file.absolute() if return_as_abs_url else file
    raise FileNotFoundError(f"{name} doesn't exists.")


def normalize_domain(raw: str) -> Optional[str]:
    """Normalize input to bare domain using urllib.parse.
    Accepts raw domain or URL, strips scheme, credentials, path/query/fragment, and port.
    """
    s = (raw or "").strip().lower()
    if not s:
        return None
    parsed = urlparse(s if "://" in s else "http://" + s)
    return parsed.hostname


def write_to_zapret_file(name: str | Path, site: str) -> bool:
    name = get_zapret_file_path(name)
    with open(name, "a", encoding="utf-8") as f:
        if check_site_in_zapret_file(name, site):
            return False
        f.write(site + "\n")
        return True


def read_from_zapret_file(name: str) -> list[str]:
    file_path = get_zapret_file_path(name)
    if file_path:
        with open(file_path, "r", encoding="utf-8") as f:
            return [
                line.strip() for line in f if line.strip() and not line.startswith("#")
            ]
    return []


def check_site_in_zapret_file(name: Path, site: str) -> bool:
    with open(name, "r", encoding="utf-8") as f:
        return any(
            line.strip().lower() == site
            for line in f
            if line.strip() and not line.startswith("#")
        )
    return False


def get_zapret_file_path(name: str) -> Optional[Path]:
    """Get zapret file path by name (general, 123, hosts, exclude)"""
    match (name):
        case "hosts":
            name = "zapret-hosts-user"
        case "exclude":
            name = "zapret-hosts-user-exclude"
        case _:
            pass
    # Check /etc/zapret first
    for file in Path("/etc/zapret").iterdir():
        if file.is_file() and file.stem == name and file.suffix == ".txt":
            return file.absolute()
    # Check /opt/zapret/ipsets as fallback
    for file in Path("/opt/zapret/ipset").iterdir():
        if file.is_file() and file.stem == name and file.suffix == ".txt":
            return file.absolute()
    return None


def get_all_zapret_files() -> list[Path]:
    files: list[Path] = []
    for file in Path("/etc/zapret").iterdir():
        if file.is_file() and file.suffix == ".txt":
            files.append(file)
    files.append(Path("/opt/zapret/ipset/zapret-hosts-user.txt"))
    files.append(Path("/opt/zapret/ipset/zapret-hosts-user-exclude.txt"))
    return files
