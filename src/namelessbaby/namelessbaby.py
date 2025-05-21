import json
from pathlib import Path
import random


baby_names: dict[str, dict[str, dict]] = json.load(Path("babynames.json"))


def name_that_baby(count: int = 1, sex=None):
    if sex == None:
        names = baby_names["girl"].keys() + baby_names["boy"].keys()
    elif sex in ["girl", "boy"]:
        names = baby_names[sex].keys()
    else:
        raise Exception(f"Invalid sex parameter: Must be 'boy' or 'girl'")
    if count > len(names):
        raise Exception(f"Invalid count parameter: Must be no more than {len(names)}")
    return random.sample(count, k=count)


def name_that_boy(count: int = 1) -> list[str] | str:
    return name_that_baby(count=count, sex="boy")


def name_that_girl(count: int = 1) -> list[str] | str:
    return name_that_baby(count=count, sex="girl")
