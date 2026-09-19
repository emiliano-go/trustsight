"""The public API stays documented and statically resolvable.

IDEs and type checkers only show a hint when a symbol has an annotation and
a docstring, and attribute descriptions come from the class docstring's
``:ivar:`` entries rather than from a string literal in the class body.  A
new field or method that ships without one degrades the public surface
silently, so the checks live here.
"""

from __future__ import annotations

import dataclasses
import inspect

import trustsight
from trustsight import api


def _public_methods(cls):
    for name, member in inspect.getmembers(cls):
        if name.startswith("_"):
            continue
        if isinstance(member, property):
            yield name, member.fget
        elif inspect.isfunction(member):
            yield name, member


def _documented_params(fn) -> list[str]:
    missing = []
    signature = inspect.signature(fn)
    for param in signature.parameters.values():
        if param.name in ("self", "cls"):
            continue
        if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
            continue
        if param.annotation is inspect.Parameter.empty:
            missing.append(param.name)
    return missing


def test_all_is_the_package_surface():
    assert set(api.__all__) == set(trustsight._API_NAMES)
    assert set(trustsight.__all__) == {"__version__", "api", *api.__all__}


def test_every_export_resolves_and_is_documented():
    for name in api.__all__:
        value = getattr(api, name)
        assert value is getattr(trustsight, name)
        if inspect.isclass(value) or inspect.isfunction(value):
            assert value.__doc__, f"{name} has no docstring"


def test_public_classes_have_annotated_methods_with_docstrings():
    for name in api.__all__:
        value = getattr(api, name)
        if not inspect.isclass(value):
            continue
        for method_name, fn in _public_methods(value):
            label = f"{name}.{method_name}"
            assert fn.__doc__, f"{label} has no docstring"
            assert not _documented_params(fn), (
                f"{label} leaves {_documented_params(fn)} unannotated"
            )
            assert inspect.signature(fn).return_annotation is not inspect.Signature.empty, (
                f"{label} has no return annotation"
            )


def test_dataclass_fields_are_named_in_the_class_docstring():
    for name in api.__all__:
        value = getattr(api, name)
        if not (inspect.isclass(value) and dataclasses.is_dataclass(value)):
            continue
        doc = value.__doc__
        for field in dataclasses.fields(value):
            if field.name.startswith("_"):
                continue
            assert f":ivar {field.name}:" in doc, (
                f"{name}.{field.name} is not documented with :ivar:"
            )
