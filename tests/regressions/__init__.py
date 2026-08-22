"""Regression suite: every past defect that reached a release, pinned.

Each test reproduces a bug that shipped at some point and names the fix
commit in its group comment.  A future change that reintroduces the defect
fails here first, before it reaches a release or a CI gate that only
catches it downstream.

One module per group; the shared recipe builders live in `helpers.py` and
the scratch-directory fixture in `conftest.py`.
"""
