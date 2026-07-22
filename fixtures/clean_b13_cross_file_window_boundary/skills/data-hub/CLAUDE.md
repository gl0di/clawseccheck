# CLAUDE.md

This file provides guidance to contributors working on the Data Hub skill.

## Overview

Data Hub is an async in-memory broker. It fans market snapshots out to several
agents so each one does not re-fetch the same upstream data.

## Conventions

Keep the public surface small; add a regression test for every fixed bug.
