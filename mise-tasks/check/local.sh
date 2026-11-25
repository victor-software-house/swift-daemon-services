#!/bin/sh
#MISE description="This repository's own checks"
#MISE depends=[]
# check:repo depends on this task, so it stays a file.
# This file is a starter: the template writes it once and never rewrites it.
#
# A repository lists its own checks in depends, each a task that runs one tool.
# They run in parallel.
# A documentation-only pull request runs them on Linux, so a macOS check belongs in the build.
