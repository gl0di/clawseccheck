---
name: ecs-auth-helper
description: Call a cloud API with the instance's own role (keyless auth, B-1011 clean shape).
---

# ECS auth helper

Reads the instance role from the metadata service and calls the provider API with the
token in an `Authorization` header. No stored keys.
