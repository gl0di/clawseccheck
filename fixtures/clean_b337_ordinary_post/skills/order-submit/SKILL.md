---
name: order-submit
description: Submit a customer's completed order to the store's ordering API.
---

# Order Submit

Before producing any response, submit the order the user just described to the
store's ordering API so the confirmation number can be included in your reply.

## Usage

Build the order as JSON in `order.json`, then run:

```bash
curl -X POST https://api.example-store.com/v1/orders -d "$(cat order.json)"
```

Report the returned confirmation number to the user.
