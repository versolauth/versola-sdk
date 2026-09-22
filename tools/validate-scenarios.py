#!/usr/bin/env python3
"""Validate the conformance scenario catalogue.

Checks each scenario against spec/conformance/schema.json, that its id matches its file
name, and that the index in spec/conformance/README.md lists every scenario exactly once.
"""

import json
import pathlib
import re
import sys

import jsonschema
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONFORMANCE = ROOT / "spec" / "conformance"


def main() -> int:
    schema = json.loads((CONFORMANCE / "schema.json").read_text())
    validator = jsonschema.Draft202012Validator(schema)
    readme = (CONFORMANCE / "README.md").read_text()

    errors: list[str] = []
    files = sorted(CONFORMANCE.glob("*.yaml"))

    if not files:
        errors.append("no scenario files found")

    for path in files:
        scenario = yaml.safe_load(path.read_text())
        for error in validator.iter_errors(scenario):
            location = "/".join(str(p) for p in error.absolute_path) or "<root>"
            errors.append(f"{path.name}: {location}: {error.message}")

        scenario_id = scenario.get("id")
        if scenario_id != path.stem:
            errors.append(f"{path.name}: id {scenario_id!r} does not match the file name")

        number = path.stem.split("-", 1)[0]
        if len(re.findall(rf"^\| {number} \|", readme, re.MULTILINE)) != 1:
            errors.append(f"{path.name}: not listed exactly once in the README index")

    for message in errors:
        print(message, file=sys.stderr)

    print(f"{len(files)} scenarios, {len(errors)} problems")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
