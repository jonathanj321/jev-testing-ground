"""Small synchronous adapter for typesafe-sdk 0.7.5."""
from pathlib import Path
from typing import Any

from PIL import Image as PILImage
from typesafe_sdk import Choice, Image, Noul, RetryPolicy, Score, TypeSafeClient


def convert_images(value: Any, base_dir: Path) -> tuple[Any, bool]:
    """Resolve and validate image markers without modifying the original input."""
    if isinstance(value, dict):
        if "$image" in value:
            if set(value) != {"$image"} or not isinstance(value["$image"], str):
                raise ValueError("Image marker must contain only a string $image path")
            path = (base_dir / value["$image"]).resolve()
            if path.suffix.lower() not in {".png", ".jpg", ".jpeg"}:
                raise ValueError(f"Unsupported image extension: {path}")
            with PILImage.open(path) as image:
                if image.format not in {"PNG", "JPEG"}:
                    raise ValueError(f"Unsupported image format: {path}")
                image.verify()
            return Image(path), True
        converted = {key: convert_images(item, base_dir) for key, item in value.items()}
        return {key: item[0] for key, item in converted.items()}, any(item[1] for item in converted.values())
    if isinstance(value, list):
        converted = [convert_images(item, base_dir) for item in value]
        return [item[0] for item in converted], any(item[1] for item in converted)
    return value, False


def build_questions(definitions: dict) -> dict:
    constructors = {"choice": Choice, "score": Score, "noul": Noul}
    questions = {}
    for name, definition in definitions.items():
        if definition.get("type") not in constructors:
            raise ValueError(f"Unsupported question type for {name}")
        questions[name] = constructors[definition["type"]](**definition)
    return questions


class JevClient:
    def __init__(self, model: str = "jev-latest") -> None:
        self.client = TypeSafeClient(model=model, retry=RetryPolicy(max_retries=0), timeout=30.0)

    def evaluate(self, case: dict, base_dir: Path) -> dict:
        state, state_images = convert_images(case["state"], base_dir)
        definitions, question_images = convert_images(case["questions"], base_dir)
        response = self.client.system_one(
            state=state, questions=build_questions(definitions),
            extra_headers={"TypeSafe-Danger-Zone-Images": "true"} if state_images or question_images else None,
        )
        return response.model_dump(mode="json")

    def close(self) -> None:
        self.client.close()
